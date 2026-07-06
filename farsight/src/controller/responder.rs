#![allow(clippy::too_many_arguments)]

use crate::{
    controller::{
        as_array_unchecked,
        protocol::{ParseError, Parser, Payload},
        receiver::Receiver,
        sender::{Sender},
    },
    database::Scanling,
    net::{
        tcp::{cookie, TcpFlags},
    },
};
use fxhash::FxHashMap;
use log::{debug, error, trace};
use std::{net::Ipv4Addr, time::{Duration, Instant}};
use std::collections::{BTreeMap, VecDeque};
use std::ops::{Add, Sub};
use anyhow::{bail};
use rand::{random, SeedableRng};
use rand_xoshiro::Xoshiro256PlusPlus;
use zerocopy::{FromBytes};
use crate::controller::completer::Completer;
use crate::controller::strategy::ip::IpAdapter;
use crate::controller::strategy::port::PortAdapter;
use crate::net::tcp::TcpHdr;

struct State {
    data: Vec<u8>,

    next_expected_seq: u32,
    next_expected_ack: u32,

    reorder_buffer: BTreeMap<u32, Vec<u8>>,

    expires_at: Instant,
}

type Connections = FxHashMap<(Ipv4Addr, u16), State>;
type Scanlings<P> = Vec<Scanling<P>>;
type Expiry = (Instant, (Ipv4Addr, u16));

pub(super) struct Responder<'umem: 'b, 'b, A: PortAdapter, I: IpAdapter, PA: Payload, P: Parser> {
    port_adapter: &'b A,
    ip_adapter: &'b I,

    payload: &'b PA,
    parser: &'b P,

    receiver: Receiver<'umem>,
    sender: Sender<'umem>,

    connections: Connections,
    pub(super) scanlings: Scanlings<P>,

    expiries: VecDeque<Expiry>,
    pending_expiry: Option<Expiry>,

    rng: Xoshiro256PlusPlus,

    seed: u64,
    max_reorder_segments: usize,
    max_reorder_bytes: usize,
    timeout: Duration,
}

impl<'umem: 'b, 'b, A: PortAdapter, I: IpAdapter, PA: Payload, P: Parser> Responder<'umem, 'b, A, I, PA, P> {
    #[inline]
    pub(super) fn new(
        receiver: Receiver<'umem>,
        sender: Sender<'umem>,
        port_adapter: &'b A,
        ip_adapter: &'b I,
        payload: &'b PA,
        parser: &'b P,
        seed: u64
    ) -> Self {
        Self {
            seed,
            max_reorder_segments: sender.shared.config.tcp.max_reorder_segments,
            max_reorder_bytes: sender.shared.config.tcp.max_reorder_bytes,
            timeout: sender.shared.timeout,

            scanlings: Vec::with_capacity(sender.shared.config.xdp.ring_size as usize),
            rng: Xoshiro256PlusPlus::seed_from_u64(seed),

            port_adapter,
            ip_adapter,
            
            payload,

            parser,
            receiver,

            sender,

            connections: FxHashMap::default(),

            expiries: VecDeque::new(),
            pending_expiry: None,
        }
    }

    #[inline]
    pub(super) fn tick(&'_ mut self, completer: &mut Completer) -> anyhow::Result<()> {
        let Responder {
            port_adapter,
            ip_adapter,
            receiver,
            payload,
            parser,
            sender,
            connections,
            scanlings,
            rng,
            max_reorder_bytes,
            max_reorder_segments,
            seed,
            timeout,
            expiries,
            pending_expiry
        } = self;

        let Some(data_batch) = receiver.receive()? else {
            return Ok(());
        };

        for data in data_batch {
            if let Err(err) = Self::process_packet(
                port_adapter,
                ip_adapter,
                payload,
                parser,
                sender,
                connections,
                expiries,
                scanlings,
                data,
                rng,
                *timeout,
                *seed,
                *max_reorder_bytes,
                *max_reorder_segments,
                completer
            ) {
                error!("error ticking controller: {:?}", err);
            }
        }

        let now = Instant::now();
        loop {
            let (expiry, key) = match pending_expiry.take() {
                Some(e) => e,
                None => match expiries.pop_front() {
                    Some(e) => e,
                    None => break,
                },
            };

            if connections.contains_key(&key) {
                if expiry > now {
                    *pending_expiry = Some((expiry, key));

                    break;
                }

                connections.remove(&key);
            }
        }

        Ok(())
    }

    #[inline]
    fn process_packet(
        adapter: &A,
        ip_adapter: &I,
        payload: &PA,
        parser: &P,
        sender: &mut Sender,
        connections: &mut FxHashMap<(Ipv4Addr, u16), State>,
        expiries: &mut VecDeque<Expiry>,
        scanlings: &mut Vec<Scanling<P>>,
        data: &mut [u8],
        rng: &mut impl rand::Rng,
        timeout: Duration,
        seed: u64,
        max_reorder_bytes: usize,
        max_reorder_segments: usize,
        completer: &mut Completer
    ) -> anyhow::Result<()> {
        let ip = Ipv4Addr::from_octets(*unsafe {
            as_array_unchecked(&data[26..30])
        });

        let tcp_start = 14 + ((data[14] & 0x0F) << 2) as usize;
        let ip_total_len = u16::from_be_bytes(*unsafe {
            as_array_unchecked(&data[16..18])
        }) as usize;

        let packet_end = usize::min(
            14 + ip_total_len,
            data.len()
        ); // to get rid of ethernet frame padding

        let data_start = tcp_start + ((data[tcp_start + 12] & 0xF0) >> 2) as usize;
        if data_start > packet_end {
            debug!("invalid packet data offset from {ip}");

            return Ok(());
        }

        let tcp_payload = &data[data_start..packet_end];
        let hdr = match TcpHdr::ref_from_bytes(&data[tcp_start..tcp_start + size_of::<TcpHdr>()]) {
            Ok(hdr) => hdr,
            Err(err) => {
                debug!("error casting header: {:?}", err);
                return Ok(())
            }
        };

        if hdr.flags.contains(TcpFlags::Rst) {
            let port = hdr.source_port.get();

            Self::record_empty(
                adapter,
                ip,
                port,
                seed,
                rng,
                sender,
                completer
            )?;

            connections.remove(&(ip, port));
        } else if hdr.flags.contains(TcpFlags::Fin) {
            Self::process_fin(
                ip,
                hdr,
                tcp_payload,

                adapter,
                ip_adapter,
                sender,
                seed,
                connections,
                scanlings,
                parser,
                rng,

                completer
            )?;
        } else if hdr.flags.contains(TcpFlags::Syn | TcpFlags::Ack) {
            Self::process_syn_ack(
                ip,
                hdr,

                adapter,
                sender,
                connections,
                expiries,
                payload,
                rng,
                timeout,
                seed,

                completer
            )?;
        } else if hdr.flags.contains(TcpFlags::Ack) {
            Self::process_ack(
                ip,
                hdr,
                tcp_payload,

                adapter,
                ip_adapter,
                sender,
                seed,
                connections,
                expiries,
                scanlings,
                parser,
                rng,
                timeout,

                max_reorder_bytes,
                max_reorder_segments,

                completer
            )?;
        }

        Ok(())
    }

    fn record_empty(
        adapter: &A,
        ip: Ipv4Addr,
        port: u16,
        seed: u64,
        rng: &mut impl rand::Rng,
        sender: &mut Sender,
        completer: &mut Completer
    ) -> anyhow::Result<()> {
        let Some(template) = adapter.on_result(ip, port, None, rng) else {
            return Ok(());
        };

        sender.send_syn(&template, seed, completer)?;

        Ok(())
    }

    fn record_hit(
        adapter: &A,
        ip: Ipv4Addr,
        port: u16,
        seed: u64,
        hash: u64,
        rng: &mut impl rand::Rng,
        sender: &mut Sender,
        completer: &mut Completer
    ) -> anyhow::Result<()> {
        let Some(template) = adapter.on_result(ip, port, Some(hash), rng) else {
            return Ok(());
        };

        sender.send_syn(&template, seed, completer)?;

        Ok(())
    }

    fn process_syn_ack(
        ip: Ipv4Addr,
        hdr: &TcpHdr,

        adapter: &A,
        sender: &mut Sender,
        connections: &mut Connections,
        expiries: &mut VecDeque<Expiry>,
        payload: &PA,
        rng: &mut impl rand::Rng,
        timeout: Duration,
        seed: u64,

        completer: &mut Completer
    ) -> anyhow::Result<()> {
        let source_port = hdr.dest_port.get();
        let port = hdr.source_port.get();
        let ack = hdr.ack.get();
        let seq = hdr.seq.get();

        let expected_ack = cookie(&ip, port, seed).wrapping_add(1);
        if ack != expected_ack {
            trace!("syn+ack with cookie mismatch from {ip}:{port}; expected {expected_ack} got {ack}");

            Self::record_empty(
                adapter,
                ip,
                port,
                seed,
                rng,
                sender,
                completer
            )?;

            return Ok(());
        }

        trace!("syn+ack from {ip}:{port}");

        let payload = match payload.build(ip, port) {
            Ok(payload) => payload,
            Err(err) => {
                // skip this server
                sender.send::<{ TcpFlags::Rst }>(
                    ip,
                    source_port,
                    port,
                    ack,
                    seq,
                    completer
                )?;

                Self::record_empty(
                    adapter,
                    ip,
                    port,
                    seed,
                    rng,
                    sender,
                    completer
                )?;

                bail!("error building payload for {ip}:{port}, skipping: {err}")
            }
        };

        let seq = seq.wrapping_add(1);
        sender.send_with_data(
            ip,
            source_port,
            port,
            ack,
            seq,
            payload,
            completer
        )?;

        let expires_at = Instant::now().add(timeout);

        expiries.push_back((expires_at, (ip, port)));
        connections.insert(
            (ip, port),
            State {
                data: Vec::new(),

                next_expected_seq: seq,
                next_expected_ack: ack.wrapping_add(payload.len() as u32),

                reorder_buffer: BTreeMap::new(),
                expires_at
            },
        );

        Ok(())
    }

    fn process_ack(
        ip: Ipv4Addr,
        hdr: &TcpHdr,
        payload: &[u8],

        port_adapter: &A,
        ip_adapter: &I,
        sender: &mut Sender,
        seed: u64,
        connections: &mut Connections,
        expiries: &mut VecDeque<Expiry>,
        scanlings: &mut Scanlings<P>,
        parser: &P,
        rng: &mut impl rand::Rng,
        timeout: Duration,

        max_reorder_bytes: usize,
        max_reorder_segments: usize,

        completer: &mut Completer
    ) -> anyhow::Result<()> {
        let source_port = hdr.dest_port.get();
        let port = hdr.source_port.get();
        let ack = hdr.ack.get();
        let seq = hdr.seq.get();

        let Some(state) = connections.get_mut(&(ip, port)) else {
            Self::record_empty(
                port_adapter,
                ip,
                port,
                seed,
                rng,
                sender,
                completer
            )?;

            sender.send::<{ TcpFlags::Rst }>(
                ip,
                source_port,
                port,
                ack,
                seq.wrapping_add(payload.len() as u32),
                completer
            )?;

            return Ok(());
        };

        if ack != state.next_expected_ack {
            trace!("ack with ack mismatch from {ip}:{port}; expected {} got {} (diff: {})", state.next_expected_ack, ack, (ack as isize).wrapping_sub(state.next_expected_ack as isize));

            return Ok(());
        }

        if seq != state.next_expected_seq {
            let diff = seq.wrapping_sub(state.next_expected_seq);
            trace!("ack with seq mismatch from {ip}:{port}; expected {} got {} (diff: {diff})", state.next_expected_seq, seq);

            if diff < 65535
                && !payload.is_empty()
                && state.reorder_buffer.len() < max_reorder_segments
            {
                let buffered_bytes: usize = state.reorder_buffer.values()
                    .map(|v| v.len())
                    .sum();

                if buffered_bytes + payload.len() <= max_reorder_bytes {
                    trace!("caching out-of-order segment from {ip}:{port} (seq: {seq}, len: {})", payload.len());

                    state.reorder_buffer.insert(seq, payload.to_vec());
                }
            }

            // send duplicate ack for retransmission
            sender.send::<{ TcpFlags::Ack }>(
                ip,
                source_port,
                port,
                state.next_expected_ack,
                state.next_expected_seq,
                completer
            )?;

            return Ok(());
        }

        if payload.is_empty() {
            trace!("ack without data from {ip}:{port}");

            return Ok(());
        }

        state.data.extend_from_slice(payload);
        state.next_expected_seq = seq.wrapping_add(payload.len() as u32);

        trace!("ack with data from {ip}:{port}");

        while let Some(buffered) = state.reorder_buffer.remove(&state.next_expected_seq) {
            trace!("stitching buffered segment for {ip}:{port} (seq: {})", state.next_expected_seq);

            state.next_expected_seq = state.next_expected_seq.wrapping_add(buffered.len() as u32);
            state.data.extend_from_slice(&buffered);
        }

        match parser.parse(&state.data) {
            Ok(banner) => {
                let state = connections.remove(&(ip, port)).unwrap();
                sender.send::<{ TcpFlags::Rst }>(
                    ip,
                    source_port,
                    port,
                    state.next_expected_ack,
                    state.next_expected_seq,
                    completer
                )?;

                ip_adapter.on_result(ip);

                Self::record_hit(
                    port_adapter,
                    ip,
                    port,
                    seed,
                    fxhash::hash64(&banner),
                    rng,
                    sender,
                    completer
                )?;

                scanlings.push(Scanling::new(ip, port, banner));
            }

            Err(ParseError::Invalid) => {
                Self::record_empty(
                    port_adapter,
                    ip,
                    port,
                    seed,
                    rng,
                    sender,
                    completer
                )?;

                let state = connections.remove(&(ip, port)).unwrap();
                sender.send::<{ TcpFlags::Rst }>(
                    ip,
                    source_port,
                    port,
                    state.next_expected_ack,
                    state.next_expected_seq,
                    completer
                )?;

                trace!("invalid data from {ip}:{port}, ignoring")
            }

            Err(ParseError::Incomplete) => {
                // we might have more data coming so we'll wait a bit longer
                state.expires_at += timeout;

                expiries.push_back((state.expires_at, (ip, port)));
                sender.send::<{ TcpFlags::Ack }>(
                    ip,
                    source_port,
                    port,
                    state.next_expected_ack,
                    state.next_expected_seq,
                    completer
                )?;
            }
        };

        Ok(())
    }

    fn process_fin(
        ip: Ipv4Addr,
        hdr: &TcpHdr,
        payload: &[u8],

        adapter: &A,
        ip_adapter: &I,
        sender: &mut Sender,
        seed: u64,
        connections: &mut Connections,
        scanlings: &mut Scanlings<P>,
        parser: &P,
        rng: &mut impl rand::Rng,

        completer: &mut Completer
    ) -> anyhow::Result<()> {
        let source_port = hdr.dest_port.get();
        let port = hdr.source_port.get();
        let ack = hdr.ack.get();
        let seq = hdr.seq.get();

        // its joever
        sender.send::<{ TcpFlags::Rst }>(
            ip,
            source_port,
            port,
            ack,
            seq.wrapping_add(1).wrapping_add(payload.len() as u32),
            completer
        )?;

        let mut state = match connections.remove(&(ip, port)) {
            Some(state) => state,
            None => {
                trace!("fin from unknown or forgotten {ip}:{port}");

                // maybe the adapter knows about it
                Self::record_empty(
                    adapter,
                    ip,
                    port,
                    seed,
                    rng,
                    sender,
                    completer
                )?;

                return Ok(())
            }
        };

        if payload.is_empty() {
            trace!("fin from {ip}:{port}");

            Self::record_empty(
                adapter,
                ip,
                port,
                seed,
                rng,
                sender,
                completer
            )?;

            return Ok(())
        }

        trace!("fin with data from {ip}:{port}");

        state.data.extend_from_slice(payload);
        match parser.parse(&state.data) {
            Ok(banner) => {
                ip_adapter.on_result(ip);

                Self::record_hit(
                    adapter,
                    ip,
                    port,
                    seed,
                    fxhash::hash64(&banner),
                    rng,
                    sender,
                    completer
                )?;

                scanlings.push(Scanling::new(ip, port, banner))
            },

            Err(ParseError::Invalid) => {
                Self::record_empty(
                    adapter,
                    ip,
                    port,
                    seed,
                    rng,
                    sender,
                    completer
                )?;

                trace!("invalid data from fin from {ip}:{port}, ignoring")
            },

            Err(ParseError::Incomplete) => {
                Self::record_empty(
                    adapter,
                    ip,
                    port,
                    seed,
                    rng,
                    sender,
                    completer
                )?;

                trace!("incomplete data from fin from {ip}:{port}, ignoring")
            }
        };

        Ok(())
    }

    #[inline]
    pub(super) fn into_inner(self) -> (Receiver<'umem>, Sender<'umem>) {
        (self.receiver, self.sender)
    }
}
