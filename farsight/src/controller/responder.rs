use crate::{
    controller::{
        as_array_unchecked,
        protocol::{ParseError, Parser, Payload},
        receiver::Receiver,
        sender::{PacketTemplate, Sender},
    },
    database::Scanling,
    net::{
        tcp::{cookie, TcpFlags},
    },
};
use fxhash::FxHashMap;
use log::{debug, error, info, trace};
use std::{
    cell::{RefCell, UnsafeCell},
    collections::HashMap,
    fmt::Debug,
    marker::PhantomData,
    net::Ipv4Addr,
    slice::IterMut,
    sync::{
        atomic::{AtomicBool, Ordering}, Arc,
        MutexGuard,
    },
    thread,
    time::{Duration, Instant},
};
use anyhow::Error;
use crate::controller::receiver::BatchGuard;

struct State {
    data: Vec<u8>,

    next_seq: Option<u32>,

    next_expected_seq: u32,
    next_expected_ack: Option<u32>,

    fin_sent: bool,

    timestamp: Instant,
}

pub(super) struct Responder<'b, PA: Payload, P: Parser> {
    payload: &'b PA,
    parser: &'b P,

    receiver: &'b RefCell<Receiver>,
    pub(super) sender: &'b mut Sender,

    ping_timeout: Duration,
    connections: FxHashMap<(Ipv4Addr, u16), State>,

    pub(super) scanlings: Vec<Scanling<P>>,
}

impl<'b, PA: Payload, P: Parser> Responder<'b, PA, P> {
    #[inline]
    pub(super) fn new(
        payload: &'b PA,
        parser: &'b P,
        sender: &'b mut Sender,
        receiver: &'b RefCell<Receiver>,
        ping_timeout: Duration
    ) -> Self {
        Self {
            scanlings: Vec::with_capacity(sender.shared.ring_size as usize),

            payload,
            parser,

            receiver,
            sender,

            ping_timeout,
            connections: FxHashMap::default(),
        }
    }

    #[inline]
    pub(super) fn tick(&'_ mut self) -> anyhow::Result<()> {
        let mut receiver = self.receiver.borrow_mut();
        let Some(data_batch) = receiver.receive()? else {
            return Ok(());
        };

        for data in data_batch {
            self.process_packet(data);
        }

        Ok(())
    }

    #[inline]
    fn process_packet<'a, 'c: 'a>(&'a mut self, data: &'c [u8]) {
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

        let seq = u32::from_be_bytes(*unsafe {
            as_array_unchecked(&data[tcp_start + 4..tcp_start + 8])
        });

        let ack = u32::from_be_bytes(*unsafe {
            as_array_unchecked(&data[tcp_start + 8..tcp_start + 12])
        });

        let ip_total_len = u16::from_be_bytes(*unsafe {
            as_array_unchecked(&data[16..18])
        }) as usize;

        let packet_end = usize::min(
            14 + ip_total_len,
            data.len()
        );

        let tcp_header_len = ((data[tcp_start + 12] & 0xF0) >> 2) as usize;
        let payload_start = tcp_start + tcp_header_len;

        let payload = &data[payload_start..packet_end];

        let flags = TcpFlags::from_bits_retain(data[tcp_start + 13]);
        if flags.contains(TcpFlags::Fin) {
            self.process_fin(ip, port, dest_port, seq, ack, payload);
        } else if flags.contains(TcpFlags::Syn | TcpFlags::Ack) {
            self.process_syn_ack(ip, port, dest_port, seq, ack);
        } else if flags.contains(TcpFlags::Ack) {
            self.process_ack(ip, port, dest_port, seq, ack, payload);
        }

        self.connections
            .retain(|_, state| state.timestamp.elapsed() < self.ping_timeout);
    }

    fn process_fin(&mut self, ip: Ipv4Addr, port: u16, dest_port: u16, seq: u32, ack: u32, payload: &[u8]) {
        trace!("fin from {ip}:{port}");

        let state = match self.connections.get_mut(&(ip, port)) {
            Some(state) => state,
            None => {
                trace!("fin from unknown or forgotten {ip}:{port}");

                self.sender.send(PacketTemplate::new(
                    TcpFlags::Rst,
                    ip,
                    dest_port,
                    port,
                    ack,
                    seq.wrapping_add(1)
                ));

                return
            }
        };

        let next_seq = match state.next_seq {
            Some(next_seq) => next_seq,
            None => return
        };

        self.sender.send(PacketTemplate::new(
            if state.fin_sent {
                TcpFlags::Ack
            } else {
                state.fin_sent = true;

                TcpFlags::Fin | TcpFlags::Ack
            },
            ip,
            dest_port,
            port,
            next_seq.wrapping_add(1),
            seq.wrapping_add(1)
        ));

        if payload.is_empty() {
            return
        }

        state.data.extend_from_slice(payload);

        let state =  self.connections.remove(&(ip, port)).unwrap();
        match self.parser.parse(ip, port, &state.data) {
            Ok(banner) => {
                self.sender.shared.reward.fetch_add(10, Ordering::AcqRel);

                self.scanlings.push(Scanling::new(ip, port, banner));
            }

            Err(ParseError::Invalid) => {
                self.sender.shared.reward.fetch_sub(1, Ordering::AcqRel);

                trace!("invalid data from FIN from {ip}:{port}, ignoring")
            }

            Err(ParseError::Incomplete) => {
                trace!("incomplete data from FIN from {ip}:{port}, ignoring")
            }
        };
    }

    fn process_syn_ack(&mut self, ip: Ipv4Addr, port: u16, dest_port: u16, seq: u32, ack: u32) {
        if ack != cookie(&ip, port, self.sender.shared.seed).wrapping_add(1)
        {
            debug!("syn+ack cookie mismatch from {ip}:{port}");

            return;
        }

        trace!("syn+ack from {ip}:{port}");

        self.sender.shared.reward.fetch_add(3, Ordering::AcqRel);

        let payload = match self.payload.build(ip, port) {
            Ok(payload) => payload,
            Err(err) => {
                error!(
                        "error building payload for {ip}:{port}, skipping: {err}"
                    );

                // skip this server
                self.sender.send(PacketTemplate::new(
                    TcpFlags::Rst,
                    ip,
                    dest_port,
                    port,
                    ack,
                    seq.wrapping_add(1)
                ));

                return;
            }
        };

        // send our payload
        self.sender.send_with_data(PacketTemplate::new(
            TcpFlags::Psh | TcpFlags::Ack,
            ip,
            dest_port,
            port,
            ack,
            seq.wrapping_add(1)
        ), payload);

        self.connections.insert(
            (ip, port),
            State {
                data: Vec::new(),

                next_seq: None,

                next_expected_seq: 0,
                next_expected_ack: Some(
                    ack.wrapping_add(payload.len() as u32),
                ),

                fin_sent: false,

                timestamp: Instant::now(),
            },
        );
    }

    fn process_ack(&mut self, ip: Ipv4Addr, port: u16, dest_port: u16, seq: u32, ack: u32, payload: &[u8]) {
        let Some(state) = self.connections.get_mut(&(ip, port)) else {
            return;
        };

        if payload.is_empty() {
            trace!("ack without data from {ip}:{port}");

            return;
        }

        if let Some(next_expected_ack) = state.next_expected_ack {
            if ack != next_expected_ack {
                trace!("ack cookie mismatch from {ip}:{port}");

                return;
            }

            state.next_expected_ack = None;
        } else if seq != state.next_expected_seq && state.fin_sent {
            trace!("ack seq mismatch from {ip}:{port}");

            self.sender.send(PacketTemplate::new(
                // fin might've been dropped
                TcpFlags::Fin | TcpFlags::Ack,
                ip,
                dest_port,
                port,
                ack,
                state.next_expected_seq
            ));

            return;
        }

        state.data.extend_from_slice(payload);
        state.next_seq = Some(ack);
        state.next_expected_seq = seq.wrapping_add(payload.len() as u32);

        trace!("ack with data from {ip}:{port}");

        match self.parser.parse(ip, port, &state.data) {
            Ok(banner) => {
                self.sender.shared.reward.fetch_add(10, Ordering::AcqRel);

                self.sender.send(PacketTemplate::new(
                    TcpFlags::Fin | TcpFlags::Ack,
                    ip,
                    dest_port,
                    port,
                    ack,
                    state.next_expected_seq
                ));

                state.fin_sent = true;

                self.scanlings.push(Scanling::new(ip, port, banner));
            }

            Err(ParseError::Invalid) => {
                self.sender.shared.reward.fetch_sub(1, Ordering::AcqRel);

                trace!("invalid data from {ip}:{port}, ignoring")
            }

            Err(ParseError::Incomplete) => {
                self.sender.send(PacketTemplate::new(
                    TcpFlags::Ack,
                    ip,
                    dest_port,
                    port,
                    ack,
                    state.next_expected_seq
                ));
            }
        };
    }
}
