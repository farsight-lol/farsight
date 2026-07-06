use crate::controller::strategy::port::PortGenerationGuard;
use crate::controller::strategy::port::PortGenerator;
use std::time::{Duration, Instant};
use crossbeam_epoch::Guard;
use rand::{SeedableRng};
use rand_xoshiro::{Xoshiro256Plus};
use crate::controller::sender::PacketTemplate;
use crate::controller::strategy::ip::IpAdapter;
use crate::controller::worker::Worker;

pub struct Feeder<'b, A: PortGenerator, I: IpAdapter> {
    rng: Xoshiro256Plus,
    index: u64,

    start: Instant,

    duration: Duration,

    port_guard: A,
    ip_adapter: &'b I,
    
    guard: Guard,

    queue: &'b Worker<PacketTemplate>,
}

impl<'b, A: PortGenerator, I: IpAdapter> Feeder<'b, A, I> {
    #[inline]
    pub fn new(
        seed: u64,
        duration: Duration,
        queue: &'b Worker<PacketTemplate>,
        port_guard: A,
        ip_adapter: &'b I
    ) -> Self {
        Self {
            rng: Xoshiro256Plus::seed_from_u64(seed),
            index: 0,

            start: Instant::now(),

            duration,

            port_guard,
            ip_adapter,
            
            guard: crossbeam_epoch::pin(),

            queue,
        }
    }

    #[inline]
    pub(crate) fn tick(&mut self) -> bool {
        let Some(guard) = self.port_guard.guard() else {
            return false;
        };

        let now = Instant::now();
        if now - self.start >= self.duration {
            return true
        }

        let addr = match self.ip_adapter.next_address(&mut self.index, &mut self.rng) {
            Some(addr) => addr,
            None => return true
        };

        self.queue.push(
            guard.generate(
                addr, 
                now, 
                &mut self.rng,
                &self.guard
            ),
            &self.guard
        );

        false
    }
}
