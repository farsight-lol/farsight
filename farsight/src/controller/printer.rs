use log::{debug, info, trace};
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

pub(super) struct Printer<'env> {
    completed: &'env AtomicUsize,
    filled: &'env AtomicUsize,

    print_every: Duration,

    last: Instant,
}

impl<'b> Printer<'b> {
    #[inline]
    pub(super) fn new(
        completed: &'b AtomicUsize,
        filled: &'b AtomicUsize,
        print_every: Duration,
    ) -> Self {
        Self {
            completed,
            filled,

            print_every,

            last: Instant::now(),
        }
    }

    #[inline]
    pub(super) fn tick(&mut self, now: Instant) {
        let elapsed = now - self.last;
        if elapsed < self.print_every {
            return;
        }

        let comp = self.completed.swap(0, Ordering::Relaxed);
        {
            let pps = comp as f64 / elapsed.as_secs_f64();
            if pps > 10_000_000. {
                info!("tx: {} mpps", (pps / 1_000_000.).round() as u64)
            } else if pps > 10_000. {
                info!("tx: {} kpps", (pps / 1_000.).round() as u64)
            } else {
                info!("tx: {} pps", pps.round() as u64)
            };
        }

        let fill = self.filled.swap(0, Ordering::Relaxed);
        {
            let pps = fill as f64 / elapsed.as_secs_f64();
            if pps > 10_000_000. {
                info!("rx: {} mpps", (pps / 1_000_000.).round() as u64)
            } else if pps > 10_000. {
                info!("rx: {} kpps", (pps / 1_000.).round() as u64)
            } else {
                info!("rx: {} pps", pps.round() as u64)
            };
        }

        trace!("total completed: {comp}");

        self.last = now;
    }
}
