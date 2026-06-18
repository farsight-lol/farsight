use crate::{
    controller::sender::Sender,
    net::range::CompiledRanges,
};
use perfect_rand::PerfectRng;
use rand::{random, RngExt, SeedableRng};
use rand_xorshift::XorShiftRng;
use std::{net::Ipv4Addr, sync::atomic::{AtomicU64, Ordering}, thread};
use std::time::{Duration, Instant};

pub(super) struct Scanner<'b> {
    sender: &'b mut Sender,

    xor_shift_rng: XorShiftRng,

    rng: &'b PerfectRng,
    ranges: &'b CompiledRanges,
    index: &'b AtomicU64,

    targets: Vec<(u16, Ipv4Addr, u16)>,

    tokens: f64,
    last_refill: Instant,
    rate: f64
}

impl<'b> Scanner<'b> {
    #[inline]
    pub(super) fn new(
        sender: &'b mut Sender,
        ranges: &'b CompiledRanges,
        rng: &'b PerfectRng,
        index: &'b AtomicU64,
        rate: f64
    ) -> Self {
        Self {
            xor_shift_rng: XorShiftRng::from_seed(random()),

            rng,
            ranges,
            index,

            targets: Vec::with_capacity(sender.shared.ring_size as usize),

            tokens: 0f64,
            last_refill: Instant::now(),

            rate,

            sender,
        }
    }

    #[inline]
    pub(super) fn tick(&mut self) -> (bool, Option<anyhow::Error>) {
        self.targets.clear();

        let mut finished = false;

        let batch = self.next_batch();
        let index = self.index.fetch_add(batch, Ordering::Relaxed);

        for index in index..index + batch {
            if index >= self.ranges.count() as u64 {
                finished = true;

                break;
            }

            let index =
                self.rng.shuffle(index)
                    as usize;

            let (ip, port) = self.ranges.index(index);
            let src_port = self.xor_shift_rng.random_range(
                self.sender.shared.source_port_start
                    ..=self.sender.shared.source_port_end,
            );

            // essentially free since pre-allocated
            self.targets.push((src_port, ip, port));
        }

        let error = self.sender.send_syn_batch(&self.targets).err();

        (finished, error)
    }

    #[inline]
    fn next_batch(&mut self) -> u64 {
        loop {
            let now = Instant::now();
            let elapsed = now.duration_since(self.last_refill).as_secs_f64();
            self.last_refill = now;

            self.tokens = (self.tokens + elapsed * self.rate).min(self.targets.capacity() as f64);

            if self.tokens < 1.0 {
                let need = 1.0 - self.tokens;
                let wait = (need / self.rate).min(0.1);
                
                thread::sleep(Duration::from_secs_f64(wait));
                
                continue;
            }

            let take = self.tokens.floor();
            self.tokens -= take;

            return take as u64;
        }
    }
}
