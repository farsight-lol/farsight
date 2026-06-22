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
use std::collections::BTreeMap;
use anyhow::{bail};
use rand::{random, SeedableRng};
use rand_xorshift::XorShiftRng;
use zerocopy::{FromBytes};
use crate::controller::completer::Completer;
use crate::controller::strategy::adapter::Adapter;
use crate::net::tcp::TcpHdr;

struct State {
    data: Vec<u8>,

    next_expected_seq: u32,
    next_expected_ack: u32,

    reorder_buffer: BTreeMap<u32, Vec<u8>>,

    timestamp: Instant,
}

type Connections = FxHashMap<(Ipv4Addr, u16), State>;
type Scanlings<P> = Vec<Scanling<P>>;

pub(super) struct Responder<'umem: 'b, 'b, A: Adapter, PA: Payload, P: Parser> {
    adapter: &'b A,

    payload: &'b PA,
    parser: &'b P,

    receiver: Receiver<'umem>,
    sender: Sender<'umem>,

    connections: Connections,
    pub(super) scanlings: Scanlings<P>,

    rng: XorShiftRng,

    // just a tad bit more cache friendly
    seed: u64,
    max_reorder_segments: usize,
    max_reorder_bytes: usize,
    timeout: Duration,
}

impl<'umem: 'b, 'b, A: Adapter, PA: Payload, P: Parser> Responder<'umem, 'b, A, PA, P> {
    #[inline]
    pub(super) fn new(
        receiver: Receiver<'umem>,
        sender: Sender<'umem>,
        adapter: &'b A,
        payload: &'b PA,
        parser: &'b P,
        seed: u64
    ) -> Self {
        Self {
            seed,
            max_reorder_segments: sender.shared.config.tcp.max_reorder_segments,
            max_reorder_bytes: sender.shared.config.tcp.max_reorder_bytes,
            timeout: sender.shared.config.ping.timeout,

            scanlings: Vec::with_capacity(sender.shared.config.xdp.ring_size as usize),
            rng: XorShiftRng::from_seed(random()),

            adapter,
            payload,

            parser,
            receiver,

            sender,

            connections: FxHashMap::default(),
        }
    }

    #[inline]
    pub(super) fn tick(&'_ mut self, completer: &mut Completer) -> anyhow::Result<()> {
        let Responder {
            adapter,
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
            timeout: _
        } = self;

        let Some(data_batch) = receiver.receive()? else {
            return Ok(());
        };

        for data in data_batch {
            if let Err(err) = Self::process_packet(
                adapter,
                payload,
                parser,
                sender,
                connections,
                scanlings,
                data,
                rng,
                *seed,
                *max_reorder_bytes,
                *max_reorder_segments,
                completer
            ) {
                error!("error ticking controller: {:?}", err);
            }
        }

        connections.retain(|_, state| state.timestamp.elapsed() < self.timeout);

        Ok(())
    }

    #[inline]
    fn process_packet(
        adapter: &A,
        payload: &PA,
        parser: &P,
        sender: &mut Sender,
        connections: &mut FxHashMap<(Ipv4Addr, u16), State>,
        scanlings: &mut Vec<Scanling<P>>,
        data: &mut [u8],
        rng: &mut XorShiftRng,
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

        let tcp_header_len = ((data[tcp_start + 12] & 0xF0) >> 2) as usize;

        let tcp_payload = &data[tcp_start + tcp_header_len..packet_end];
        let hdr = match TcpHdr::ref_from_bytes(&data[tcp_start..tcp_start + size_of::<TcpHdr>()]) {
            Ok(hdr) => hdr,
            Err(err) => {
                debug!("error casting header: {:?}", err);
                return Ok(())
            }
        };

        if hdr.flags.contains(TcpFlags::Rst) {
            let port = hdr.source_port.get();

            adapter.on_result::<false>(ip, port, rng);
            connections.remove(&(ip, port));
        } else if hdr.flags.contains(TcpFlags::Fin) {
            Self::process_fin(
                ip,
                hdr,
                tcp_payload,

                adapter,
                sender,
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
                payload,
                rng,
                seed,

                completer
            )?;
        } else if hdr.flags.contains(TcpFlags::Ack) {
            Self::process_ack(
                ip,
                hdr,
                tcp_payload,

                adapter,
                sender,
                connections,
                scanlings,
                parser,
                rng,

                max_reorder_bytes,
                max_reorder_segments,

                completer
            )?;
        }

        Ok(())
    }

    fn process_syn_ack(
        ip: Ipv4Addr,
        hdr: &TcpHdr,

        adapter: &A,
        sender: &mut Sender,
        connections: &mut Connections,
        payload: &PA,
        rng: &mut XorShiftRng,
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

            adapter.on_result::<false>(ip, port, rng);

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

                adapter.on_result::<false>(ip, port, rng);

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

        connections.insert(
            (ip, port),
            State {
                data: Vec::new(),

                next_expected_seq: seq,
                next_expected_ack: ack.wrapping_add(payload.len() as u32),

                reorder_buffer: BTreeMap::new(),

                timestamp: Instant::now(),
            },
        );

        Ok(())
    }

    fn process_ack(
        ip: Ipv4Addr,
        hdr: &TcpHdr,
        payload: &[u8],

        adapter: &A,
        sender: &mut Sender,
        connections: &mut Connections,
        scanlings: &mut Scanlings<P>,
        parser: &P,
        rng: &mut XorShiftRng,

        max_reorder_bytes: usize,
        max_reorder_segments: usize,

        completer: &mut Completer
    ) -> anyhow::Result<()> {
        let source_port = hdr.dest_port.get();
        let port = hdr.source_port.get();
        let ack = hdr.ack.get();
        let seq = hdr.seq.get();

        let Some(state) = connections.get_mut(&(ip, port)) else {
            adapter.on_result::<false>(ip, port, rng);

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

                adapter.on_result::<true>(ip, port, rng);

                scanlings.push(Scanling::new(ip, port, banner));
            }

            Err(ParseError::Invalid) => {
                adapter.on_result::<false>(ip, port, rng);

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
                state.timestamp = Instant::now();
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
        sender: &mut Sender,
        connections: &mut Connections,
        scanlings: &mut Scanlings<P>,
        parser: &P,
        rng: &mut XorShiftRng,

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
                adapter.on_result::<false>(ip, port, rng);

                return Ok(())
            }
        };

        if payload.is_empty() {
            trace!("fin from {ip}:{port}");

            adapter.on_result::<false>(ip, port, rng);

            return Ok(())
        }

        trace!("fin with data from {ip}:{port}");

        state.data.extend_from_slice(payload);
        match parser.parse(&state.data) {
            Ok(banner) => {
                adapter.on_result::<true>(ip, port, rng);

                scanlings.push(Scanling::new(ip, port, banner))
            },

            Err(ParseError::Invalid) => {
                adapter.on_result::<false>(ip, port, rng);

                trace!("invalid data from fin from {ip}:{port}, ignoring")
            },

            Err(ParseError::Incomplete) => {
                adapter.on_result::<false>(ip, port, rng);

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
