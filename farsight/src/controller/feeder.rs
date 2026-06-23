use std::{hint, thread};
use std::time::{Duration, Instant};
use rand::{SeedableRng};
use rand_xoshiro::{Xoshiro256Plus};
use crate::controller::shared::SharedData;
use crate::controller::strategy::ip::IpAdapter;
use crate::controller::strategy::port::PortAdapter;

pub struct Feeder<'b, A: PortAdapter, I: IpAdapter> {
    rng: Xoshiro256Plus,
    index: u64,

    start: Instant,

    rate: f64,
    tokens: f64,
    last_refill: Instant,

    duration: Duration,
    port_adapter: &'b A,
    ip_adapter: &'b I,
}

impl<'b, A: PortAdapter, I: IpAdapter> Feeder<'b, A, I> {
    #[inline]
    pub fn new(
        shared: SharedData,
        seed: u64,
        duration: Duration,
        port_adapter: &'b A,
        ip_adapter: &'b I
    ) -> Self {
        Self {
            rng: Xoshiro256Plus::seed_from_u64(seed),
            index: 0,

            start: Instant::now(),

            rate: shared.config.strategy.max_rate,
            tokens: 0.0,
            last_refill: Instant::now(),

            duration,
            port_adapter,
            ip_adapter
        }
    }

    #[inline]
    pub(crate) fn tick(&mut self) -> bool {
        if self.port_adapter.at_capacity() {
            hint::spin_loop();

            return false
        }

        let pass = self.next_batch();
        if self.last_refill.duration_since(self.start) >= self.duration {
            return true;
        }

        if pass {
            return false
        }

        let addr = match self.ip_adapter.next_address(&mut self.index, &mut self.rng) {
            Some(addr) => addr,
            None => return true
        };

        self.port_adapter.enqueue(addr, self.last_refill, &mut self.rng);

        false
    }


    #[inline]
    fn next_batch(&mut self) -> bool {
        loop {
            let now = Instant::now();
            let elapsed = now.duration_since(self.last_refill).as_secs_f64();
            self.last_refill = now;

            self.tokens = (self.tokens + elapsed * self.rate).min(1.0);

            if self.tokens < 1.0 {
                let need = 1.0 - self.tokens;
                let wait = (need / self.rate).min(0.1);

                thread::sleep(Duration::from_secs_f64(wait));

                continue;
            }

            let take = self.tokens.floor();
            self.tokens -= take;

            return take as u64 == 0;
        }
    }
}
