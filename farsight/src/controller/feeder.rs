use std::ops::Add;
use crate::controller::strategy::port::{Expiry, PortBatcher, PortGenerationGuard};
use crate::controller::strategy::port::PortGenerator;
use std::time::{Duration, Instant};
use crossbeam_epoch::Guard;
use rand::{SeedableRng};
use rand_xoshiro::{Xoshiro256Plus};
use crate::controller::shared::SharedData;
use crate::controller::strategy::ip::IpAdapter;
use crate::net::tcp::PacketTemplate;

pub struct Feeder<'env, B: PortBatcher<'env>, A: PortGenerator, I: IpAdapter> {
    rng: Xoshiro256Plus,
    index: u64,

    start: Instant,

    duration: Duration,
    timeout: Duration,

    port_batcher: B,
    port_guard: A,
    ip_adapter: &'env I,

    guard: Guard,
    
    batch_size: usize,
    result_batch: Vec<PacketTemplate>,
    expiries_batch: Vec<Expiry>
}

impl<'env, B: PortBatcher<'env>, A: PortGenerator, I: IpAdapter> Feeder<'env, B, A, I> {
    #[inline]
    pub fn new(
        shared: SharedData,
        seed: u64,
        duration: Duration,
        port_batcher: B,
        port_guard: A,
        ip_adapter: &'env I
    ) -> Self {
        let batch_size = shared.config.session.batch_size;
        
        Self {
            rng: Xoshiro256Plus::seed_from_u64(seed),
            index: 0,

            start: Instant::now(),

            guard: crossbeam_epoch::pin(),

            duration,
            timeout: shared.timeout,

            port_batcher,
            port_guard,
            ip_adapter,

            batch_size,
            result_batch: Vec::with_capacity(batch_size),
            expiries_batch: Vec::with_capacity(batch_size)
        }
    }

    #[inline]
    pub(crate) fn tick(&mut self) -> bool {
        let now = Instant::now();
        if now - self.start >= self.duration {
            return true
        }

        self.result_batch.clear();
        self.expiries_batch.clear();

        let timeout = now.add(self.timeout);
        for _ in 0..self.batch_size {
            let Some(guard) = self.port_guard.guard() else {
                continue;
            };

            let addr = match self.ip_adapter.next_address(&mut self.index, &mut self.rng) {
                Some(addr) => addr,
                None => return true
            };

            let result = guard.generate(
                addr,
                &mut self.rng
            );

            self.result_batch.push(result);
            self.expiries_batch.push((timeout, addr));
        }

        self.port_batcher.batch(
            &self.result_batch,
            &self.expiries_batch,
            &self.guard
        );

        false
    }
}
