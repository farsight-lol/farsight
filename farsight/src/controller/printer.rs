use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use log::info;

pub(super) struct Printer<'b> {
    completed: &'b AtomicUsize,

    print_every: Duration,
    
    last: Instant,
    last_comp: usize
}

impl<'b> Printer<'b> {
    #[inline]
    pub(super) fn new(completed: &'b AtomicUsize, print_every: Duration) -> Self {
        Self {
            completed,

            print_every,
            
            last: Instant::now(),
            last_comp: 0
        }
    }
    
    #[inline]
    pub(super) fn tick(&mut self) {
        let elapsed = self.last.elapsed();
        if elapsed < self.print_every {
            return;
        }

        let comp = self.completed.load(Ordering::Acquire);
        let pps = (comp - self.last_comp) as f64 / elapsed.as_secs_f64();

        if pps > 10_000_000. {
            info!("{} mpps", (pps / 1_000_000.).round() as u64)
        } else if pps > 10_000. {
            info!("{} kpps", (pps / 1_000.).round() as u64)
        } else {
            info!("{} pps", pps.round() as u64)
        };

        self.last_comp = comp;
        self.last = Instant::now();
    }
}
