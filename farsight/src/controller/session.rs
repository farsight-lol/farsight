use crate::{
    controller::{
        completer::Completer

        ,
        scanner::Scanner,
        sender::Sender,
        shared::SharedData,
    },
    net::range::CompiledRanges,
};
use perfect_rand::PerfectRng;
use std::{fmt::Debug, sync::{atomic::AtomicU64, Arc, Mutex}, thread, time::{Duration, Instant}};
use std::ops::DerefMut;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::Scope;
use crossbeam_queue::SegQueue;
use log::info;
use tokio::runtime::Handle;
use crate::controller::printer::Printer;
use crate::database::Database;

pub struct Session<'b> {
    shared: SharedData,

    completers: &'b SegQueue<Completer>,
    senders: &'b SegQueue<Sender>,

    ranges: CompiledRanges
}

impl<'b> Session<'b> {
    #[inline]
    pub(super) fn new(
        shared: SharedData,
        senders: &'b SegQueue<Sender>,
        completers: &'b SegQueue<Completer>,
        ranges: CompiledRanges,
    ) -> Result<Self, anyhow::Error> {
        Ok(Self {
            shared,

            completers,
            senders,

            ranges
        })
    }

    #[inline]
    pub fn start(self, duration: Duration) {
        let done = AtomicBool::new(false);

        let index = AtomicU64::new(0);
        let rng = PerfectRng::new(
            self.ranges.count() as u64,
            self.shared.seed,
            3,
        );

        let completed = AtomicUsize::new(0);

        thread::scope(|scope| {
            // gotta tell the compiler which ones are borrowed
            // because rust doesn't have a feature such
            // as "move this into the closure but not that" that isn't explicit as this
            // also self.senders and self.receivers are references so no need to take an extra reference here
            let done = &done;
            let index = &index;
            let rng = &rng;
            let completed = &completed;
            let ranges = &self.ranges;

            loop {
                let Some(mut sender) = self.senders.pop() else {
                    break
                };

                scope.spawn(move || {
                    let mut scanner = Scanner::new(
                        ranges,
                        rng,
                        index,
                        &mut sender,
                    );

                    loop {
                        if done.load(Ordering::Acquire) {
                            break;
                        }

                        scanner.tick().expect("ticking scanner");
                    }

                    // push back into the pool
                    self.senders.push(sender);
                });
            }

            loop {
                let Some(mut completer) = self.completers.pop() else {
                    break
                };

                scope.spawn(move || {
                    loop {
                        if done.load(Ordering::Acquire) {
                            break;
                        }

                        if completer.tick() {
                            completed.fetch_add(1, Ordering::Acquire);
                        }
                    }

                    // push back into the pool
                    self.completers.push(completer);
                });
            }

            scope.spawn(|| {
                let mut printer = Printer::new(completed, self.shared.print_every);

                loop {
                    if done.load(Ordering::Acquire) {
                        break;
                    }

                    printer.tick();
                }
            });
            
            thread::sleep(duration);

            done.store(true, Ordering::Release);
        })
    }
}
