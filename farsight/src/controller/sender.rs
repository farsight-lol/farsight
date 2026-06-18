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
use std::sync::Arc;
use anyhow::Context;
use crate::xdp::umem::Umem;

pub(super) struct Sender {
    tcp_checksum: u32,
    ipv4_checksum: u32,

    umem: Arc<Umem>,
    
    pub(super) shared: SharedData,
    pub(super) socket: Socket,

    tx: Producer<Descriptor>,
}

// optimized for our TCP_PACKET constant
impl Sender {
    #[inline]
    pub(super) fn new(
        shared: SharedData,
        umem: Arc<Umem>,
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

                if shared.checksum_offload {
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
            tcp_checksum: if shared.checksum_offload {
                6 + 28 + source_ip_sum
            } else {
                6 + 28
                    + tcp::sum_body(&TCP_PACKET[34..62])
                    + source_ip_sum
            },

            ipv4_checksum: tcp::sum_body(&TCP_PACKET[14..34]) + source_ip_sum,

            umem,
            
            shared,
            socket,

            tx,
        })
    }

    #[inline]
    pub(super) fn send_syn_batch(&mut self, packets: &[(u16, Ipv4Addr, u16)]) -> anyhow::Result<()> {
        if packets.is_empty() {
            return Ok(());
        }

        let index = loop {
            if self.tx.flags().needs_wakeup() {
                self.socket.sendto().context("waking up tx ring")?;
            }

            if let Some(index) = self.tx.reserve(packets.len() as u32) {
                break index;
            }
        };

        for (i, (src_port, ip, port)) in packets.iter().enumerate() {
            let index = index + i as u32;
            let seq = cookie(ip, *port, self.shared.seed);

            let desc = &mut self.tx[index];

            let data = self.umem.of_desc(desc);
            let hdr = unsafe { &mut *(data.as_mut_ptr() as *mut EthTcpIpHdr) };

            desc.len = 62;

            hdr.ack = 0u32.to_be();
            hdr.dest_addr = *ip;
            hdr.seq = seq.to_be();

            let dest_sum = tcp::ipv4_sum(ip.as_octets());

            hdr.dest_port = port.to_be();
            hdr.source_port = src_port.to_be();
            hdr.ip_checksum = (!fold(self.ipv4_checksum + dest_sum)).to_be();

            // branch prediction gets rid of this pretty quickly
            if self.shared.checksum_offload {
                hdr.tcp_checksum = fold(self.tcp_checksum + dest_sum).to_be();
            } else {
                hdr.tcp_checksum = (!fold(
                    self.tcp_checksum
                        + dest_sum
                        + *src_port as u32
                        + *port as u32
                        + (seq >> 16)
                        + (seq & 0xFFFF)
                        + 0x0002
                )).to_be();
            }

            hdr.flags = TcpFlags::Syn.bits();
        }

        self.tx.submit(packets.len() as u32);

        if self.tx.flags().needs_wakeup() {
            self.socket.sendto().context("waking up tx ring")?;
        }

        Ok(())
    }

    pub(super) fn send(&mut self, template: PacketTemplate) -> anyhow::Result<()> {
        let index = loop {
            if self.tx.flags().needs_wakeup() {
                self.socket.sendto().context("waking up tx ring")?;
            }

            if let Some(index) = self.tx.reserve(1) {
                break index;
            }
        };

        let desc = &mut self.tx[index];

        let data = self.umem.of_desc(desc);
        let hdr = unsafe { &mut *(data.as_mut_ptr() as *mut EthTcpIpHdr) };

        desc.len = 62;
        hdr.dest_addr = template.ip;
        hdr.ack = template.ack.to_be();
        hdr.seq = template.seq.to_be();

        let dest_sum = tcp::ipv4_sum(template.ip.as_octets());
        hdr.dest_port = template.port.to_be();
        hdr.source_port = template.source_port.to_be();
        hdr.ip_checksum = (!fold(self.ipv4_checksum + dest_sum)).to_be();

        let flags = template.flags.bits();
        if self.shared.checksum_offload {
            hdr.tcp_checksum = fold(self.tcp_checksum + dest_sum).to_be();
        } else {
            hdr.tcp_checksum = (!fold(
                self.tcp_checksum
                    + dest_sum
                    + template.source_port as u32
                    + template.port as u32
                    + (template.seq >> 16)
                    + (template.seq & 0xFFFF)
                    + (template.ack >> 16)
                    + (template.ack & 0xFFFF)
                    + flags as u32
            )).to_be();
        }

        hdr.flags = flags;

        self.tx.submit(1);

        if self.tx.flags().needs_wakeup() {
            self.socket.sendto().context("waking up tx ring")?;
        }

        Ok(())
    }

    pub(super) fn send_with_data(&mut self, template: PacketTemplate, body: &[u8]) -> anyhow::Result<()> {
        let index = loop {
            if self.tx.flags().needs_wakeup() {
                self.socket.sendto().context("waking up tx ring")?;
            }

            if let Some(index) = self.tx.reserve(1) {
                break index;
            }
        };

        let desc = &mut self.tx[index];

        let data = self.umem.of_desc(desc);
        let hdr = unsafe { &mut *(data.as_mut_ptr() as *mut EthTcpIpHdr) };

        hdr.dest_addr = template.ip;
        hdr.ack = template.ack.to_be();
        hdr.seq = template.seq.to_be();

        let dest_sum = tcp::ipv4_sum(template.ip.as_octets());

        let data_len = body.len();

        desc.len = 62 + data_len as u32;
        hdr.len = (48 + data_len as u16).to_be();

        unsafe {
            hint::assert_unchecked(data.len() >= 62 + data_len);
            hint::assert_unchecked(
                body.len() <= data[62..62 + data_len].len(),
            );
        }

        data[62..62 + data_len].copy_from_slice(body);

        hdr.dest_port = template.port.to_be();
        hdr.source_port = template.source_port.to_be();
        hdr.ip_checksum = (!fold(self.ipv4_checksum + dest_sum + data_len as u32)).to_be();

        let flags = template.flags.bits();
        if self.shared.checksum_offload {
            hdr.tcp_checksum = fold(self.tcp_checksum + dest_sum).to_be();
        } else {
            hdr.tcp_checksum = (!fold(
                self.tcp_checksum
                    + dest_sum
                    + template.source_port as u32
                    + template.port as u32
                    + (template.seq >> 16)
                    + (template.seq & 0xFFFF)
                    + (template.ack >> 16)
                    + (template.ack & 0xFFFF)
                    + flags as u32
                    + data_len as u32
                    + tcp::sum_body(body)
            )).to_be();
        }

        hdr.flags = template.flags.bits();

        self.tx.submit(1);

        if self.tx.flags().needs_wakeup() {
            self.socket.sendto().context("waking up tx ring")?;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct PacketTemplate {
    flags: TcpFlags,
    ip: Ipv4Addr,

    source_port: u16,
    port: u16,

    seq: u32,
    ack: u32
}

impl PacketTemplate {
    #[inline]
    pub const fn new(
        flags: TcpFlags,
        ip: Ipv4Addr,
        source_port: u16,
        port: u16,
        seq: u32,
        ack: u32
    ) -> Self {
        Self {
            flags,
            ip,
            source_port,
            port,
            seq,
            ack
        }
    }
}
