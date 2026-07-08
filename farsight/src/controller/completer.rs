use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Instant};
use crate::controller::shared::SharedData;
use crate::xdp::ring::Consumer;

pub struct Completer<'b> {
    cr: Consumer<u64>,
    completed: &'b AtomicUsize,

    rate: f64,
    tokens: f64,
    last_refill: Instant,

    batch_size: u32,
}

impl<'b> Completer<'b> {
    #[inline]
    pub fn new(
        shared: SharedData,
        cr: Consumer<u64>,
        rate: f64,
        completed: &'b AtomicUsize
    ) -> Self {
        Self {
            cr,
            completed,

            rate,
            tokens: 0.0,
            last_refill: Instant::now(),

            batch_size: shared.config.xdp.batches.completion
        }
    }

    #[inline]
    pub(super) fn tick(&mut self) -> Option<()> {
        let batch = self.next_batch();
        if let Some((_, count)) = self.cr.peek(batch) {
            self.cr.release(count);

            self.completed.fetch_add(count as usize, Ordering::Relaxed);
            self.tokens += (batch - count) as f64;

            Some(())
        } else {
            self.tokens += batch as f64;

            None
        }
    }

    #[inline]
    fn next_batch(&mut self) -> u32 {
        let now = Instant::now();
        let elapsed = (now - self.last_refill).as_secs_f64();
        self.last_refill = now;

        self.tokens = (self.tokens + elapsed * self.rate).min(self.batch_size as f64);
        if self.tokens < 1.0 {
            return 0;
        }

        let take = self.tokens.floor();
        self.tokens -= take;

        take as u32
    }

    #[inline]
    pub(super) fn into_inner(self) -> Consumer<u64> {
        self.cr
    }
}
