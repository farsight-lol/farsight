use crate::{
    controller::sender::{PacketTemplate, Sender},
    net::{
        range::CompiledRanges,
        tcp::{cookie, TcpFlags},
    },
};
use perfect_rand::PerfectRng;
use std::sync::{
    atomic::{AtomicU64, Ordering}, Arc,
    MutexGuard,
};

pub(super) struct Scanner<'b> {
    sender: &'b mut Sender,

    rng: &'b PerfectRng,
    ranges: &'b CompiledRanges,
    index: &'b AtomicU64,
}

impl<'b> Scanner<'b> {
    #[inline]
    pub(super) fn new(
        ranges: &'b CompiledRanges,
        rng: &'b PerfectRng,
        index: &'b AtomicU64,
        sender: &'b mut Sender,
    ) -> Self {
        Self {
            sender,

            rng,
            ranges,
            index,
        }
    }

    #[inline]
    pub(super) fn tick(&mut self) -> Result<(), anyhow::Error> {
        let index = self.rng.shuffle(self.index.fetch_add(1, Ordering::Acquire))
            as usize;

        let (ip, port) = self.ranges.index(index);

        let cookie = cookie(&ip, port, self.sender.shared.seed);
        _ = self.sender.send(PacketTemplate::new(
            TcpFlags::Syn,
            ip,
            None,
            port,
            cookie,
            0,
            None,
        ));

        Ok(())
    }
}
