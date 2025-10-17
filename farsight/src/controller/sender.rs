use crate::{
    controller::{copy_from_slice_unchecked, shared::SharedData},
    net::{
        tcp,
        tcp::{finalize_checksum, TcpFlags, TCP_PACKET},
    },
    xdp::{
        ring::{Descriptor, Producer},
        socket::Socket,
        tx_metadata::TxMetadata,
        umem::TX_METADATA_LEN,
    },
};
use libc::{XDP_TXMD_FLAGS_CHECKSUM, XDP_TX_METADATA};
use rand::{
    random, Rng
    ,
    SeedableRng,
};
use rand_xorshift::XorShiftRng;
use std::{net::Ipv4Addr, ptr};

pub(super) struct Sender {
    source_ip_sum: u32,
    ipv4_checksum: u32,

    pub(super) shared: SharedData,
    socket: Socket,

    tx: Producer<Descriptor>,

    rng: XorShiftRng,
}

impl Sender {
    #[inline]
    pub(super) fn new(
        shared: SharedData,
        socket: Socket,
        mut tx: Producer<Descriptor>,
        starting_frame: u32,
    ) -> Result<Self, anyhow::Error> {
        for index in starting_frame..starting_frame + tx.size() {
            let meta_addr = index as usize * shared.umem.frame_size() as usize;
            let addr = meta_addr + TX_METADATA_LEN;

            {
                // this is fine since it's a ring
                // it just wraps overflows
                let desc = &mut tx[index];

                desc.addr = addr as u64;
                desc.options = XDP_TX_METADATA;
            }

            unsafe {
                ptr::write(
                    shared.umem.as_ptr().add(meta_addr).cast(),
                    TxMetadata::request(XDP_TXMD_FLAGS_CHECKSUM as u64, 34, 16),
                );
            }

            unsafe {
                let data = shared.umem.as_ptr().add(addr);

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
            source_ip_sum,
            ipv4_checksum: 50487 + source_ip_sum,

            shared,
            socket,

            tx,

            rng: XorShiftRng::from_seed(random()),
        })
    }

    pub(super) fn send(
        &mut self,
        template: PacketTemplate,
    ) -> Result<(), anyhow::Error> {
        let index = loop {
            if self.tx.flags().needs_wakeup() {
                _ = self.socket.sendto();
            }

            if let Some(index) = self.tx.reserve(1) {
                break index;
            }
        };

        unsafe {
            let mut len = 28;

            let desc = &mut self.tx[index];
            let data = self.shared.umem.as_ptr().add(desc.addr as usize);

            *data.add(47) = template.flags.bits();

            copy_from_slice_unchecked(data.add(30), template.ip.as_octets());
            copy_from_slice_unchecked(
                data.add(34),
                &template
                    .source_port
                    .unwrap_or_else(|| {
                        self.rng
                            .random_range(self.shared.source_port_range.clone())
                    })
                    .to_be_bytes(),
            );

            copy_from_slice_unchecked(
                data.add(36),
                &template.port.to_be_bytes(),
            );
            copy_from_slice_unchecked(
                data.add(38),
                &template.seq.to_be_bytes(),
            );
            copy_from_slice_unchecked(
                data.add(42),
                &template.ack.to_be_bytes(),
            );

            let dest_sum = tcp::ipv4_sum(template.ip.as_octets());

            let mut ipv4_checksum =
                finalize_checksum(self.ipv4_checksum + dest_sum);
            if let Some(body) = template.body {
                let data_len = body.len();

                desc.len = (TCP_PACKET.len() + data_len) as u32;
                len += data_len;

                copy_from_slice_unchecked(
                    data.add(16),
                    &(48u16 + data_len as u16).to_be_bytes(),
                );
                copy_from_slice_unchecked(data.add(TCP_PACKET.len()), body);

                ipv4_checksum = ipv4_checksum.wrapping_sub(data_len as u16);
            } else {
                desc.len = TCP_PACKET.len() as u32;
            }

            copy_from_slice_unchecked(
                data.add(24),
                &ipv4_checksum.to_be_bytes(),
            );
            copy_from_slice_unchecked(
                data.add(50),
                &tcp::raw_partial(self.source_ip_sum + dest_sum, len)
                    .to_be_bytes(),
            );
        }

        self.tx.submit(1);

        Ok(())
    }
}

#[derive(Debug)]
pub struct PacketTemplate<'b> {
    flags: TcpFlags,
    ip: Ipv4Addr,

    // randomly chooses if None
    source_port: Option<u16>,
    port: u16,

    seq: u32,
    ack: u32,

    body: Option<&'b [u8]>,
}

impl<'b> PacketTemplate<'b> {
    #[inline]
    pub const fn new(
        flags: TcpFlags,
        ip: Ipv4Addr,
        source_port: Option<u16>,
        port: u16,
        seq: u32,
        ack: u32,
        body: Option<&'b [u8]>,
    ) -> Self {
        Self {
            flags,
            ip,
            source_port,
            port,
            seq,
            ack,
            body,
        }
    }
}
