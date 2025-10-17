use crate::{
    controller::shared::SharedData,
    xdp::{
        ring::{Consumer, Descriptor, Producer},
        socket::Socket
        ,
    },
};
use anyhow::Context;
use libc::{XSK_UNALIGNED_BUF_ADDR_MASK, XSK_UNALIGNED_BUF_OFFSET_SHIFT};
use std::{
    ops::Deref

    ,
    slice::from_raw_parts
    ,
};

pub(super) struct Receiver {
    shared: SharedData,
    queue_id: u32,
    socket: Socket,

    fr: Producer<u64>,
    rx: Consumer<Descriptor>,
}

impl Receiver {
    #[inline]
    pub(super) fn new(
        shared: SharedData,
        queue_id: u32,
        socket: Socket,
        mut fr: Producer<u64>,
        rx: Consumer<Descriptor>,
        starting_frame: u32,
    ) -> Result<Self, anyhow::Error> {
        let size = fr.size();
        let index = fr.reserve(size).context("reserving fill frames")?;

        for i in 0..size {
            fr[index + i] =
                ((starting_frame + i) * shared.umem.frame_size()) as u64;
        }

        fr.submit(size);

        Ok(Self {
            shared,
            queue_id,
            socket,

            fr,
            rx,
        })
    }

    #[inline]
    pub(super) fn receive<'c, 'b>(
        &'c mut self,
    ) -> Result<ReadGuard<'c, 'b>, anyhow::Error> {
        let fill_index = loop {
            if self.fr.flags().needs_wakeup() {
                _ = self.socket.recvfrom();
            }

            if let Some(index) = self.fr.reserve(1) {
                break index;
            }
        };

        let index = self.rx.peek(1).context("peeking rx ring")?;

        let desc = &self.rx[index];

        let comp_addr = desc.addr & XSK_UNALIGNED_BUF_ADDR_MASK;
        let addr = (desc.addr >> XSK_UNALIGNED_BUF_OFFSET_SHIFT) as usize
            + comp_addr as usize;

        Ok(ReadGuard {
            data: unsafe {
                from_raw_parts(
                    self.shared.umem.as_ptr().add(addr),
                    desc.len as usize,
                )
            },
            fr: &mut self.fr,
            rx: &self.rx,

            fill_index,
            comp_addr,
        })
    }
}

pub(super) struct ReadGuard<'c, 'b> {
    data: &'b [u8],
    fr: &'c mut Producer<u64>,
    rx: &'c Consumer<Descriptor>,

    fill_index: u32,
    comp_addr: u64,
}

impl<'c, 'b> Deref for ReadGuard<'c, 'b> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.data
    }
}

impl<'c, 'b> Drop for ReadGuard<'c, 'b> {
    #[inline]
    fn drop(&mut self) {
        self.rx.release(1);

        self.fr[self.fill_index] = self.comp_addr;
        self.fr.submit(1);
    }
}
