use crate::{
    controller::{
        completer::Completer, printer::Printer, scanner::Scanner,
        sender::Sender, shared::SharedData,
    }
    ,
    net::range::CompiledRanges,
};
use crossbeam_queue::SegQueue;
use perfect_rand::PerfectRng;
use std::{hint, sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering}, thread, time::Duration};
use std::time::Instant;
use log::error;

pub struct Session<'b> {
    shared: SharedData,
    senders: &'b SegQueue<Sender>,
    ranges: CompiledRanges,
}

impl<'b> Session<'b> {
    #[inline]
    pub(super) fn new(
        shared: SharedData,
        senders: &'b SegQueue<Sender>,
        ranges: CompiledRanges,
    ) -> Result<Self, anyhow::Error> {
        Ok(Self {
            shared,
            senders,
            ranges,
        })
    }

    #[inline]
    pub fn start(self, duration: Duration) {
        let rate = self.shared.max_rate as f64 / self.senders.len() as f64;
        let done = AtomicBool::new(false);

        let index = AtomicU64::new(0);
        let rng =
            PerfectRng::new(self.ranges.count() as u64, self.shared.seed, 3);

        thread::scope(|scope| {
            // gotta tell the compiler which ones are borrowed
            // because rust doesn't have a feature such
            // as "move this into the closure but not that" that isn't as explicit as this
            // also self.senders and self.receivers are references so no need to take an extra reference here
            let done = &done;
            let index = &index;
            let rng = &rng;
            let ranges = &self.ranges;

            loop {
                let Some(mut sender) = self.senders.pop() else {
                    break;
                };

                scope.spawn(move || {
                    {
                        let mut scanner = Scanner::new(
                            &mut sender,
                            ranges,
                            rng,
                            index,
                            rate
                        );

                        loop {
                            if done.load(Ordering::Acquire) {
                                break;
                            }

                            let (finished, error) = scanner.tick();
                            if let Some(error) = error {
                                error!("{error:?}");
                            }

                            done.store(finished, Ordering::Release);
                        }
                    }

                    // push back into the pool
                    self.senders.push(sender);
                });
            }

            let start = Instant::now();
            loop {
                if done.load(Ordering::Acquire) {
                    break;
                }

                if start.elapsed() > duration {
                    done.store(true, Ordering::Release);

                    break;
                }

                hint::spin_loop();
            }
        })
    }
}
