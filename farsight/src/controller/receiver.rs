use crate::{
    controller::shared::SharedData,
    xdp::{
        ring::{Consumer, Descriptor, Producer},
        socket::Socket,
    },
};
use anyhow::Context;
use libc::{XSK_UNALIGNED_BUF_ADDR_MASK, XSK_UNALIGNED_BUF_OFFSET_SHIFT};
use std::slice::from_raw_parts;
use std::sync::Arc;
use log::error;
use crate::xdp::umem::Umem;

pub(super) struct Receiver {
    umem: Arc<Umem>,
    socket: Socket,

    fr: Producer<u64>,
    rx: Consumer<Descriptor>,
}

impl Receiver {
    #[inline]
    pub(super) fn new(
        umem: Arc<Umem>,
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
    pub(super) fn receive(&mut self) -> Result<Option<BatchGuard<'_>>, anyhow::Error> {
        let Some((rx_start, count)) = self.rx.peek(self.rx.size()) else {
            return Ok(None);
        };

        let fill_start = loop {
            if self.fr.flags().needs_wakeup() {
                self.socket.recvfrom().context("kicking fill ring")?;
            }

            if let Some(index) = self.fr.reserve(count) {
                break index;
            }
        };

        Ok(Some(BatchGuard {
            umem: self.umem.clone(),
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

pub(super) struct BatchGuard<'c> {
    umem: Arc<Umem>,
    fr: &'c mut Producer<u64>,
    rx: &'c Consumer<Descriptor>,
    socket: Socket,

    rx_start: u32,
    fill_start: u32,
    count: u32,
    cursor: u32,
}

impl<'c> Iterator for BatchGuard<'c> {
    type Item = &'c [u8];

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
            from_raw_parts(
                self.umem.as_ptr().add(addr),
                desc.len as usize,
            )
        })
    }
}

impl<'c> Drop for BatchGuard<'c> {
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
