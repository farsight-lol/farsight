use crate::{
    controller::shared::SharedData,
    xdp::{
        ring::{Consumer, Descriptor, Producer},
        socket::Socket,
    },
};
use anyhow::Context;
use libc::{XSK_UNALIGNED_BUF_ADDR_MASK, XSK_UNALIGNED_BUF_OFFSET_SHIFT};
use std::slice::{from_raw_parts, from_raw_parts_mut};
use std::sync::Arc;
use log::error;
use crate::xdp::umem::Umem;

pub(super) struct Receiver<'umem> {
    umem: &'umem Umem,
    socket: Socket,

    fr: Producer<u64>,
    rx: Consumer<Descriptor>,
}

impl<'umem> Receiver<'umem> {
    #[inline]
    pub(super) fn new(
        umem: &'umem Umem,
        socket: Socket,
        mut fr: Producer<u64>,
        rx: Consumer<Descriptor>,
        starting_frame: u32,
    ) -> Result<Self, anyhow::Error> {
        let size = fr.size();

        let index = fr.reserve(size).context("reserving fill frames")?;
        for i in 0..size {
            fr[index + i] = ((starting_frame + i) * umem.frame_size()) as u64;
        }

        fr.submit(size);

        if fr.flags().needs_wakeup() {
            socket.recvfrom().context("kicking fill ring")?;
        }

        Ok(Self {
            umem,
            socket,

            fr,
            rx,
        })
    }

    #[inline]
    pub(super) fn receive(&mut self) -> Result<Option<BatchGuard<'umem, '_>>, anyhow::Error> {
        let Some((rx_start, count)) = self.rx.peek(self.rx.size()) else {
            return Ok(None);
        };

        if self.fr.flags().needs_wakeup() {
            self.socket.recvfrom().context("kicking fill ring")?;
        }

        let fill_start = self.fr.reserve(count)
            .context("reserving fill ring, leak somewhere?")?;

        Ok(Some(BatchGuard {
            umem: self.umem,
            fr: &mut self.fr,
            rx: &self.rx,
            socket: self.socket.clone(),

            rx_start,
            fill_start,
            count,
            cursor: 0,
        }))
    }
}

pub(super) struct BatchGuard<'umem: 'c, 'c> {
    umem: &'umem Umem,
    fr: &'c mut Producer<u64>,
    rx: &'c Consumer<Descriptor>,
    socket: Socket,

    rx_start: u32,
    fill_start: u32,
    count: u32,
    cursor: u32,
}

impl<'umem: 'c, 'c> Iterator for BatchGuard<'umem, 'c> {
    type Item = &'c mut [u8];

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.count {
            return None;
        }

        let desc = &self.rx[self.rx_start + self.cursor];
        let comp_addr = desc.addr & XSK_UNALIGNED_BUF_ADDR_MASK;
        let addr = (desc.addr >> XSK_UNALIGNED_BUF_OFFSET_SHIFT) as usize
            + comp_addr as usize;

        // write fill frame back incrementally as we consume
        self.fr[self.fill_start + self.cursor] = comp_addr;
        self.cursor += 1;

        Some(unsafe {
            from_raw_parts_mut(
                self.umem.as_ptr().add(addr),
                desc.len as usize,
            )
        })
    }
}

impl<'umem: 'c, 'c> Drop for BatchGuard<'umem, 'c> {
    #[inline]
    fn drop(&mut self) {
        for i in self.cursor..self.count {
            let desc = &self.rx[self.rx_start + i];
            let comp_addr = desc.addr & XSK_UNALIGNED_BUF_ADDR_MASK;

            self.fr[self.fill_start + i] = comp_addr;
        }

        self.rx.release(self.count);
        self.fr.submit(self.count);

        if self.fr.flags().needs_wakeup() {
            if let Err(err) = self.socket.recvfrom().context("kicking fill ring") {
                error!("failed to kick fill ring: {}", err);
            }
        }
    }
}
