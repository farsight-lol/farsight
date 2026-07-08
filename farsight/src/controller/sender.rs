use crate::{
    controller::{copy_from_slice_unchecked, shared::SharedData},
    net::{
        tcp,
        tcp::{cookie, fold, EthTcpIpHdr, TcpFlags, TCP_PACKET},
    },
    xdp::{
        ring::{Descriptor, Producer},
        socket::Socket,
        tx_metadata::TxMetadata,
    },
};
use libc::{XDP_TXMD_FLAGS_CHECKSUM, XDP_TX_METADATA};
use std::{hint, net::Ipv4Addr, ptr};
use std::mem::{ManuallyDrop, MaybeUninit};
use std::ops::Deref;
use std::sync::Arc;
use anyhow::Context;
use log::debug;
use zerocopy::FromBytes;
use crate::controller::completer::Completer;
use crate::net::tcp::PacketTemplate;
use crate::xdp::umem::Umem;

pub struct Sender<'umem> {
    tcp_checksum: u32,
    ipv4_checksum: u32,

    umem: &'umem Umem,

    pub(super) shared: SharedData,
    pub(super) socket: Socket,

    tx: Producer<Descriptor>,

    // just a tad bit more cache friendly
    checksum_offload: bool,
}

// optimized for our TCP_PACKET constant
impl<'umem> Sender<'umem> {
    #[inline]
    pub(super) fn new(
        shared: SharedData,
        umem: &'umem Umem,
        socket: Socket,
        mut tx: Producer<Descriptor>,
        starting_frame: u32,
    ) -> Result<Self, anyhow::Error> {
        for index in starting_frame..starting_frame + tx.size() {
            let meta_addr = index as usize * umem.frame_size() as usize;
            let addr = meta_addr + TxMetadata::LEN;

            {
                // this is fine since it's a ring
                // it just wraps if index overflows
                let desc = &mut tx[index];

                desc.addr = addr as u64;

                if shared.config.xdp.checksum_offload {
                    desc.options = XDP_TX_METADATA;

                    unsafe {
                        ptr::write(
                            umem.as_ptr().add(meta_addr).cast(),
                            TxMetadata::request(
                                XDP_TXMD_FLAGS_CHECKSUM as u64,
                                34,  // start of the TCP header
                                16, // offset of the checksum field
                                0   // idk
                            ),
                        );
                    }
                }
            }

            unsafe {
                let data = umem.as_ptr().add(addr);

                copy_from_slice_unchecked(data, &TCP_PACKET);

                copy_from_slice_unchecked(data, shared.gateway.as_octets());
                copy_from_slice_unchecked(
                    data.add(6),
                    shared.interface.as_octets(),
                );

                copy_from_slice_unchecked(
                    data.add(26),
                    shared.source_ip.as_octets(),
                );
            }
        }

        let source_ip_sum = tcp::ipv4_sum(shared.source_ip.as_octets());
        Ok(Self {
            tcp_checksum: if shared.config.xdp.checksum_offload {
                6 + 28 + source_ip_sum
            } else {
                6 + 28
                    + tcp::sum_body(&TCP_PACKET[34..62])
                    + source_ip_sum
            },

            ipv4_checksum: tcp::sum_body(&TCP_PACKET[14..34]) + source_ip_sum,

            checksum_offload: shared.config.xdp.checksum_offload,

            umem,

            shared,
            socket,

            tx,
        })
    }

    #[inline]
    pub(super) fn send_syn_batch(&mut self, packets: &mut Vec<PacketTemplate>, seed: u64, completer: &mut Completer) -> anyhow::Result<()> {
        let batch_size = packets.len();
        let index = loop {
            if self.tx.flags().needs_wakeup() {
                self.socket.sendto().context("waking up tx ring")?;
            }

            if let Some(index) = self.tx.reserve(batch_size as u32) {
                break index;
            }

            completer.tick();
        };

        for (i, packet) in packets.drain(..).enumerate() {
            let PacketTemplate { source_port, ip, destination_port } = packet;

            let index = index + i as u32;
            let seq = cookie(&ip, destination_port, seed);

            let desc = &mut self.tx[index];

            let data = self.umem.of_desc(desc);
            let hdr = match EthTcpIpHdr::mut_from_bytes(&mut data[..size_of::<EthTcpIpHdr>()]) {
                Ok(x) => x,
                Err(err) => {
                    debug!("header cast failed: {err:?}");
                    continue
                }
            };

            desc.len = 62;

            hdr.dest_addr = ip.octets();
            hdr.ack.set(0);
            hdr.seq.set(seq);
            hdr.len.set(48);

            let dest_sum = tcp::ipv4_sum(ip.as_octets());

            hdr.dest_port.set(destination_port);
            hdr.source_port.set(source_port);
            hdr.ip_checksum.set(!fold(self.ipv4_checksum + dest_sum));

            hdr.tcp_checksum.set(
                // branch prediction gets rid of this pretty quickly
                if self.checksum_offload {
                    fold(self.tcp_checksum + dest_sum)
                } else {
                    !fold(
                        self.tcp_checksum
                            + dest_sum
                            + source_port as u32
                            + destination_port as u32
                            + (seq >> 16)
                            + (seq & 0xFFFF)
                            + 0b00000010
                    )
                }
            );

            hdr.flags = TcpFlags::Syn;
        }

        self.tx.submit(batch_size as u32);
        if self.tx.flags().needs_wakeup() {
            self.socket.sendto().context("waking up tx ring")?;
        }

        Ok(())
    }

    #[inline]
    pub(super) fn send_syn(&mut self, packet: &PacketTemplate, seed: u64, completer: &mut Completer) -> anyhow::Result<()> {
        let index = loop {
            if self.tx.flags().needs_wakeup() {
                self.socket.sendto().context("waking up tx ring")?;
            }

            if let Some(index) = self.tx.reserve(1) {
                break index;
            }

            completer.tick();
        };

        let &PacketTemplate {
            source_port,
            ip,
            destination_port
        } = packet;

        let seq = cookie(&ip, destination_port, seed);

        let desc = &mut self.tx[index];

        let data = self.umem.of_desc(desc);
        let hdr = match EthTcpIpHdr::mut_from_bytes(&mut data[..size_of::<EthTcpIpHdr>()]) {
            Ok(x) => x,
            Err(err) => {
                debug!("header cast failed: {err:?}");

                return Ok(())
            }
        };

        desc.len = 62;

        hdr.dest_addr = ip.octets();
        hdr.ack.set(0);
        hdr.seq.set(seq);
        hdr.len.set(48);

        let dest_sum = tcp::ipv4_sum(ip.as_octets());

        hdr.dest_port.set(destination_port);
        hdr.source_port.set(source_port);
        hdr.ip_checksum.set(!fold(self.ipv4_checksum + dest_sum));

        hdr.tcp_checksum.set(
            // branch prediction gets rid of this pretty quickly
            if self.checksum_offload {
                fold(self.tcp_checksum + dest_sum)
            } else {
                !fold(
                    self.tcp_checksum
                        + dest_sum
                        + source_port as u32
                        + destination_port as u32
                        + (seq >> 16)
                        + (seq & 0xFFFF)
                        + 0b00000010
                )
            }
        );

        hdr.flags = TcpFlags::Syn;

        self.tx.submit(1);
        if self.tx.flags().needs_wakeup() {
            self.socket.sendto().context("waking up tx ring")?;
        }

        Ok(())
    }

    pub(super) fn send<const FLAGS: TcpFlags>(
        &mut self,
        ip: Ipv4Addr,
        source_port: u16,
        port: u16,
        seq: u32,
        ack: u32,
        completer: &mut Completer
    ) -> anyhow::Result<()> {
        let index = loop {
            if self.tx.flags().needs_wakeup() {
                self.socket.sendto().context("waking up tx ring")?;
            }

            if let Some(index) = self.tx.reserve(1) {
                break index;
            }

            completer.tick();
        };

        let desc = &mut self.tx[index];

        let data = self.umem.of_desc(desc);
        let hdr = match EthTcpIpHdr::mut_from_bytes(&mut data[..size_of::<EthTcpIpHdr>()]) {
            Ok(x) => x,
            Err(err) =>  {
                debug!("header cast failed: {err:?}");
                return Ok(())
            }
        };

        desc.len = 62;
        hdr.len.set(48);

        hdr.dest_addr = ip.octets();
        hdr.ack.set(ack);
        hdr.seq.set(seq);

        let dest_sum = tcp::ipv4_sum(ip.as_octets());
        hdr.dest_port.set(port);
        hdr.source_port.set(source_port);
        hdr.ip_checksum.set(!fold(self.ipv4_checksum + dest_sum));

        hdr.tcp_checksum.set(
            if self.checksum_offload {
                fold(self.tcp_checksum + dest_sum)
            } else {
                !fold(
                    self.tcp_checksum
                        + dest_sum
                        + source_port as u32
                        + port as u32
                        + (seq >> 16)
                        + (seq & 0xFFFF)
                        + (ack >> 16)
                        + (ack & 0xFFFF)
                        + FLAGS.bits() as u32
                )
            }
        );

        hdr.flags = FLAGS;

        self.tx.submit(1);
        if self.tx.flags().needs_wakeup() {
            self.socket.sendto().context("waking up tx ring")?;
        }

        Ok(())
    }

    pub(super) fn send_with_data(
        &mut self,
        ip: Ipv4Addr,
        source_port: u16,
        port: u16,
        seq: u32,
        ack: u32,
        body: &[u8],
        completer: &mut Completer
    ) -> anyhow::Result<()> {
        let index = loop {
            if self.tx.flags().needs_wakeup() {
                self.socket.sendto().context("waking up tx ring")?;
            }

            if let Some(index) = self.tx.reserve(1) {
                break index;
            }

            completer.tick();
        };

        let desc = &mut self.tx[index];
        let data = self.umem.of_desc(desc);

        let data_len = body.len();
        unsafe {
            hint::assert_unchecked(data.len() >= 62 + data_len);
            hint::assert_unchecked(
                body.len() <= data[62..62 + data_len].len(),
            );
        }

        data[62..62 + data_len].copy_from_slice(body);

        let hdr = match EthTcpIpHdr::mut_from_bytes(&mut data[..size_of::<EthTcpIpHdr>()]) {
            Ok(x) => x,
            Err(err) =>  {
                debug!("header cast failed: {err:?}");
                return Ok(())
            }
        };

        hdr.dest_addr = ip.octets();
        hdr.ack.set(ack);
        hdr.seq.set(seq);

        let dest_sum = tcp::ipv4_sum(ip.as_octets());

        desc.len = 62 + data_len as u32;
        hdr.len.set(48 + data_len as u16);

        hdr.dest_port.set(port);
        hdr.source_port.set(source_port);
        hdr.ip_checksum.set(!fold(self.ipv4_checksum + dest_sum + data_len as u32));

        hdr.tcp_checksum.set(
            if self.checksum_offload {
                fold(self.tcp_checksum + dest_sum)
            } else {
                !fold(
                    self.tcp_checksum
                        + dest_sum
                        + source_port as u32
                        + port as u32
                        + (seq >> 16)
                        + (seq & 0xFFFF)
                        + (ack >> 16)
                        + (ack & 0xFFFF)
                        + 0b00011000
                        + data_len as u32
                        + tcp::sum_body(body)
                )
            }
        );

        hdr.flags = TcpFlags::Psh | TcpFlags::Ack;

        self.tx.submit(1);

        if self.tx.flags().needs_wakeup() {
            self.socket.sendto().context("waking up tx ring")?;
        }

        Ok(())
    }
}
