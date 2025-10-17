use crate::{
    controller::{
        completer::Completer, receiver::Receiver, sender::Sender,
        shared::SharedData,
    },
    xdp::socket::{BindFlags, Socket},
};
use anyhow::{bail, Context};
use aya::maps::{MapData, XskMap};
use log::info;
use std::os::fd::AsRawFd;

pub(super) enum Xsk {
    Base(BindFlags),
    Shared(Socket),
}

impl Xsk {
    // this assumes that we're binding to different queue ids (which we are)
    #[inline]
    pub(super) fn create(
        self,
        socks: &mut XskMap<&mut MapData>,
        shared_data: SharedData,
        interface_index: u32,
        queue_id: u32,
        ring_size: u32,
    ) -> Result<(Socket, Sender, Completer, Receiver), anyhow::Error> {
        let socket = Socket::new().context("initializing socket")?;

        let (flags, shared_umem_fd) = match self {
            Xsk::Base(flags) => {
                let mut reg = shared_data.umem.as_reg();
                socket.set_umem_reg(&reg)
                    .or_else(|_| {
                        info!("error setting umem reg, retrying - this may occur with some kernels");

                        reg.remove_flags();
                        socket.set_umem_reg(&reg)
                    })
                    .context("setting umem reg")?;

                (BindFlags::NeedWakeup | flags, 0)
            }

            Xsk::Shared(socket) => {
                (BindFlags::SharedUmem, socket.as_raw_fd() as u32)
            }
        };

        let (tx, fr, rx, cr) = {
            let allocator =
                socket.rings().context("initializing ring allocator")?;

            (
                allocator.tx(ring_size).context("initializing tx ring")?,
                allocator.fr(ring_size).context("initializing fr ring")?,
                allocator.rx(ring_size).context("initializing rx ring")?,
                allocator.cr(ring_size).context("initializing cr ring")?,
            )
        };

        socket
            .bind(flags, interface_index, queue_id, shared_umem_fd)
            .context("binding socket")?;

        socks
            .set(queue_id, socket.clone(), 0)
            .context("setting socket fd")?;

        Ok((
            socket.clone(),
            Sender::new(
                shared_data.clone(),
                socket.clone(),
                tx,
                2 * queue_id * ring_size,
            )
            .context("initializing spewer")?,
            Completer::new(cr),
            Receiver::new(
                shared_data,
                queue_id,
                socket,
                fr,
                rx,
                (2 * queue_id + 1) * ring_size,
            )
            .context("initializing receiver")?,
        ))
    }

    // this doesn't assume we're binding to different queue_ids
    #[inline]
    pub(super) fn sender_only(
        self,
        shared_data: SharedData,
        interface_index: u32,
        queue_id: u32,
        queue_count: u32,
        ring_size: u32,
    ) -> Result<(Socket, Sender), anyhow::Error> {
        let socket = Socket::new().context("initializing socket")?;

        let (flags, shared_umem_fd) = match self {
            Xsk::Shared(socket) => {
                (BindFlags::SharedUmem, socket.as_raw_fd() as u32)
            }

            _ => bail!("only shared sockets are supported"),
        };

        let tx = {
            let allocator =
                socket.rings().context("initializing ring allocator")?;

            allocator.tx(ring_size).context("initializing tx ring")?
        };

        socket
            .bind(flags, interface_index, queue_id, shared_umem_fd)
            .context("binding socket")?;

        Ok((
            socket.clone(),
            Sender::new(
                shared_data.clone(),
                socket.clone(),
                tx,
                (queue_count + queue_id) * ring_size,
            )
            .context("initializing spewer")?,
        ))
    }
}
