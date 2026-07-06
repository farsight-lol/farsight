use crate::{
    controller::sender::Sender,
};
use crossbeam_epoch::Guard;
use crate::controller::completer::Completer;
use crate::controller::sender::PacketTemplate;
use crate::controller::worker::{Steal, Stealer};

pub(super) struct Scanner<'umem: 'b, 'b> {
    sender: Sender<'umem>,
    seed: u64,

    targets: Vec<PacketTemplate>,
    stealer: Stealer<'b, PacketTemplate>,
    
    guard: Guard
}

impl<'umem: 'b, 'b> Scanner<'umem, 'b> {
    #[inline]
    pub(super) fn new(
        sender: Sender<'umem>,
        seed: u64,
        stealer: Stealer<'b, PacketTemplate>
    ) -> Self {
        Self {
            targets: Vec::with_capacity(sender.shared.config.xdp.ring_size as usize),

            sender,
            seed,

            stealer,
            
            guard: crossbeam_epoch::pin()
        }
    }

    #[inline]
    pub(super) fn tick(&mut self, completer: &mut Completer) -> Option<anyhow::Error> {
        loop {
            match self.stealer.steal_batch(&mut self.targets, &self.guard) {
                Steal::Empty => return None,
                Steal::Success(()) => return self.sender.send_syn_batch(
                    &mut self.targets,
                    self.seed,
                    completer
                ).err(),
                Steal::Retry => continue
            }
        }
    }

    #[inline]
    pub(super) fn into_inner(self) -> Sender<'umem> {
        self.sender
    }
}
