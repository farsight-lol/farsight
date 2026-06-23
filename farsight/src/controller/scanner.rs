use crate::{
    controller::sender::Sender,
};
use std::{net::Ipv4Addr};
use crate::controller::completer::Completer;
use crate::controller::strategy::port::PortAdapter;

pub(super) struct Scanner<'umem: 'b, 'b, A: PortAdapter> {
    adapter: &'b A,

    targets: Vec<(u16, Ipv4Addr, u16)>,

    sender: Sender<'umem>,
    seed: u64
}

impl<'umem: 'b, 'b, A: PortAdapter> Scanner<'umem, 'b, A> {
    #[inline]
    pub(super) fn new(
        sender: Sender<'umem>,
        adapter: &'b A,
        seed: u64
    ) -> Self {
        Self {
            adapter,

            targets: Vec::with_capacity(sender.shared.config.xdp.ring_size as usize),

            sender,

            seed
        }
    }

    #[inline]
    pub(super) fn tick(&mut self, completer: &mut Completer) -> Option<anyhow::Error> {
        self.targets.clear();

        let cap = self.targets.capacity();
        self.adapter.recv_into(&mut self.targets, cap);

        self.sender.send_syn_batch(&self.targets, self.seed, completer).err()
    }

    #[inline]
    pub(super) fn into_inner(self) -> Sender<'umem> {
        self.sender
    }
}
