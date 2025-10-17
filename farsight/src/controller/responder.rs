use crate::{
    controller::{
        as_array_unchecked,
        protocol::{Parser, ParseError, Payload},
        receiver::Receiver,
        sender::{PacketTemplate, Sender},
    },
    net::{
        range::CompiledRanges,
        tcp::{cookie, TcpFlags},
    },
};
use anyhow::Context;
use crossbeam_queue::SegQueue;
use log::{debug, error, info, trace};
use perfect_rand::PerfectRng;
use std::{
    collections::HashMap,
    fmt::Debug,
    marker::PhantomData,
    net::Ipv4Addr,
    slice::IterMut,
    sync::{atomic::AtomicBool, Arc, MutexGuard},
    thread,
    time::{Duration, Instant},
};
use std::borrow::Cow;
use serde::Serialize;
use ttlhashmap::TtlHashMap;
use crate::database::Scanling;

struct State {
    data: Vec<u8>,

    next_seq: Option<u32>,

    next_expected_seq: u32,
    next_expected_ack: Option<u32>,

    fin_sent: bool,
}

pub(super) struct Responder<'b, PA: Payload, P: Parser> {
    payload: &'b PA,
    parser: &'b P,

    receiver: &'b mut Receiver,
    sender: &'b mut Sender,

    connections: TtlHashMap<(Ipv4Addr, u16), State>,
}

impl<'b, PA: Payload, P: Parser> Responder<'b, PA, P> {
    #[inline]
    pub(super) fn new(
        payload: &'b PA,
        parser: &'b P,
        sender: &'b mut Sender,
        receiver: &'b mut Receiver,
        ping_timeout: Duration,
    ) -> Self {
        Self {
            payload,
            parser,

            receiver,
            sender,

            connections: TtlHashMap::new(ping_timeout),
        }
    }

    #[inline]
    pub(super) fn tick(&'_ mut self) -> Result<Option<Scanling<P>>, anyhow::Error> {
        let Ok(data) = self.receiver.receive() else {
            return Ok(None);
        };

        let ip = Ipv4Addr::from_octets(*unsafe {
            as_array_unchecked(&data[26..30])
        });

        let tcp_start = 14 + ((data[14] & 0x0F) << 2) as usize;
        let port = u16::from_be_bytes(*unsafe {
            as_array_unchecked(&data[tcp_start..tcp_start + 2])
        });

        let dest_port = u16::from_be_bytes(*unsafe {
            as_array_unchecked(&data[tcp_start + 2..tcp_start + 4])
        });

        let ack = u32::from_be_bytes(*unsafe {
            as_array_unchecked(&data[tcp_start + 8..tcp_start + 12])
        });

        let seq = u32::from_be_bytes(*unsafe {
            as_array_unchecked(&data[tcp_start + 4..tcp_start + 8])
        });

        let flags = TcpFlags::from_bits_retain(data[tcp_start + 13]);
        if flags.intersects(TcpFlags::Rst) {
            trace!("RST from {ip}:{port}");
        } else if flags.intersects(TcpFlags::Fin) {
            let Some(state) = self.connections.get_mut(&(ip, port)) else {
                trace!("FIN from unknown or forgotten {ip}:{port}");

                _ = self.sender.send(PacketTemplate::new(
                    TcpFlags::Ack,
                    ip,
                    Some(dest_port),
                    port,
                    ack,
                    seq.wrapping_add(1),
                    None,
                ));

                return Ok(None);
            };

            let Some(next_seq) = state.next_seq else {
                return Ok(None);
            };

            _ = self.sender.send(PacketTemplate::new(
                if state.fin_sent {
                    TcpFlags::Ack
                } else {
                    state.fin_sent = true;

                    TcpFlags::Fin | TcpFlags::Ack
                },
                ip,
                Some(dest_port),
                port,
                next_seq,
                seq.wrapping_add(1),
                None,
            ));

            if !state.data.is_empty() {
                self.connections.remove(&(ip, port));
            }
        } else if flags.contains(TcpFlags::Syn | TcpFlags::Ack) {
            if ack != cookie(&ip, port, self.sender.shared.seed).wrapping_add(1)
            {
                debug!("syn+ack cookie mismatch from {ip}:{port}");

                return Ok(None);
            }

            trace!("syn+ack from {ip}:{port}");

            let payload = match self.payload.build(ip, port) {
                Ok(payload) => payload,
                Err(err) => {
                    error!(
                        "error building payload for {ip}:{port}, skipping: {err}"
                    );

                    // skip this server
                    _ = self.sender.send(PacketTemplate::new(
                        TcpFlags::Rst,
                        ip,
                        Some(dest_port),
                        port,
                        ack,
                        seq.wrapping_add(1),
                        None,
                    ));

                    return Ok(None);
                }
            };

            // send our payload
            _ = self.sender.send(PacketTemplate::new(
                TcpFlags::Psh | TcpFlags::Ack,
                ip,
                Some(dest_port),
                port,
                ack,
                seq.wrapping_add(1),
                Some(payload),
            ));

            self.connections.insert(
                (ip, port),
                State {
                    data: vec![],

                    next_seq: None,

                    next_expected_seq: 0,
                    next_expected_ack: Some(
                        ack.wrapping_add(payload.len() as u32),
                    ),

                    fin_sent: false,
                },
            );
        } else if flags.intersects(TcpFlags::Ack) {
            let Some(state) = self.connections.get_mut(&(ip, port)) else {
                trace!("ack from unknown or forgotten ip {ip}:{port}");

                return Ok(None);
            };

            let tcp_header_len = ((data[tcp_start + 12] & 0xF0) >> 2) as usize;
            let payload_start = tcp_start + tcp_header_len;

            let payload = &data[payload_start..];
            if data.is_empty() {
                trace!("ack without data from {ip}:{port}");

                return Ok(None);
            }

            if let Some(next_expected_ack) = state.next_expected_ack {
                if ack != next_expected_ack {
                    trace!("ack cookie mismatch from {ip}:{port}");

                    return Ok(None);
                }

                state.next_expected_ack = None;
            } else if seq != state.next_expected_seq {
                trace!("ack seq mismatch from {ip}:{port}");

                _ = self.sender.send(PacketTemplate::new(
                    if state.fin_sent {
                        // fin might've been dropped
                        TcpFlags::Fin | TcpFlags::Ack
                    } else {
                        TcpFlags::Ack
                    },
                    ip,
                    Some(dest_port),
                    port,
                    ack,
                    state.next_expected_seq,
                    None,
                ));

                return Ok(None);
            }

            state.data.extend_from_slice(payload);
            state.next_seq = Some(ack);
            state.next_expected_seq = seq.wrapping_add(payload.len() as u32);

            trace!("ack with data from {ip}:{port}");

            match self.parser.parse(ip, port, &state.data) {
                Ok(banner) => {
                    _ = self.sender.send(PacketTemplate::new(
                        TcpFlags::Fin | TcpFlags::Ack,
                        ip,
                        Some(dest_port),
                        port,
                        ack,
                        state.next_expected_seq,
                        None,
                    ));

                    state.fin_sent = true;

                    return Ok(Some(Scanling::new(
                        ip,
                        port,
                        banner
                    )));
                }

                Err(ParseError::Invalid) => {
                    self.connections.remove(&(ip, port));
                }

                Err(ParseError::Incomplete) => {
                    _ = self.sender.send(PacketTemplate::new(
                        TcpFlags::Ack,
                        ip,
                        Some(dest_port),
                        port,
                        ack,
                        state.next_expected_seq,
                        None,
                    ));
                }
            };
        }

        Ok(None)
    }
}
