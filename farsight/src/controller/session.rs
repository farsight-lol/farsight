use crate::{
    controller::{
        completer::Completer, printer::Printer, scanner::Scanner,
        sender::Sender, shared::SharedData,
    },
    net::range::CompiledRanges,
};
use perfect_rand::PerfectRng;
use std::{sync::atomic::{AtomicBool, AtomicUsize, Ordering}, thread, time::Duration};
use std::iter::zip;
use std::time::Instant;
use anyhow::Context;
use crossbeam_queue::SegQueue;
use futures::executor::block_on;
use log::{debug, error, info};
use rand::{random, SeedableRng};
use rand_xorshift::XorShiftRng;
use tokio::runtime::{Handle, Runtime, TryCurrentError};
use crate::controller::DestructedResponder;
use crate::controller::protocol::{Parser, Payload};
use crate::controller::receiver::Receiver;
use crate::controller::responder::Responder;
use crate::controller::strategy::adapter::{Adapter};
use crate::controller::strategy::graph::BannerCorrelationGraph;
use crate::database::{Database, Scanling};
use crate::xdp::ring::Consumer;

pub struct Session<'umem: 'b, 'b, A: Adapter> {
    shared: SharedData,
    database: &'b mut Database,
    saturators: &'b mut Vec<(Sender<'umem>, DestructedResponder<'umem>)>,
    ranges: CompiledRanges,
    adapter: A
}

impl<'umem: 'b, 'b, A: Adapter> Session<'umem, 'b, A> {
    #[inline]
    pub(super) async fn new(
        shared: SharedData,
        database: &'b mut Database,
        saturators: &'b mut Vec<(Sender<'umem>, DestructedResponder<'umem>)>,
        ranges: CompiledRanges,
        seed_ports: &[u16]
    ) -> Result<Self, anyhow::Error> {
        Ok(Self {
            adapter: A::new(
                shared.clone(),
                database,
                seed_ports
            ).await.context("creating adapter")?,

            database,
            shared,
            saturators,
            ranges,
        })
    }

    #[inline]
    pub fn start(self, duration: Duration, payload: &impl Payload, parser: &impl Parser) {
        info!("starting session");

        let completed = AtomicUsize::new(0);
        let done = AtomicBool::new(false);

        let queue = SegQueue::new();

        thread::scope(|scope| {
            scope.spawn(|| {
                let future = spawn_printer_and_database(
                    self.shared.clone(),
                    self.database,
                    &self.adapter,
                    &done,
                    &completed,
                    &queue
                );

                match Handle::try_current() {
                    Ok(handle) => handle.block_on(future),
                    Err(_) => Runtime::new().unwrap().block_on(future)
                }
            });

            let handles: Vec<_> = self.saturators.drain(..)
                .map(|(sender, (receiver, sender_responder, cr))|
                    scope.spawn(|| spawn_saturator(
                        Scanner::new(
                            sender,
                            &self.adapter,
                        ),

                        Responder::new(
                            receiver,
                            sender_responder,
                            &self.adapter,
                            payload,
                            parser
                        ),

                        Completer::new(
                            cr,
                            &completed
                        ),

                        &done,
                        &queue
                    ))
                ).collect();

            let mut index = 0;
            let mut feeder_rng = XorShiftRng::from_seed(random());

            let start = Instant::now();
            let rng = PerfectRng::new(self.ranges.count() as u64, self.shared.seed, 3);

            loop {
                if start.elapsed() >= duration {
                    break;
                }

                if index >= self.ranges.count() as u64 {
                    break;
                }

                let shuffled = rng.shuffle(index) as usize;
                let ip = self.ranges.index(shuffled);

                self.adapter.enqueue_address(ip, &mut feeder_rng);

                index += 1;
            }

            debug!("finished session; waiting for threads to finish up...");

            thread::sleep(self.shared.config.ping.timeout);
            done.store(true, Ordering::Release);

            for handle in handles {
                self.saturators.push(
                    handle.join().unwrap()
                );
            }
        });

        info!("exiting session");
    }
}

async fn spawn_printer_and_database(
    shared: SharedData,
    database: &mut Database,
    adapter: &impl Adapter,
    done: &AtomicBool,
    completed: &AtomicUsize,
    queue: &SegQueue<Scanling<impl Parser>>
) {
    let mut batch = Vec::with_capacity(shared.config.database.flush_capacity);
    let mut last_flush = Instant::now();

    let mut printer = Printer::new(completed, shared.config.controller.print_every);

    loop {
        printer.tick();

        if let Some(scanling) = queue.pop() {
            debug!("hit: {scanling:?}");

            batch.push(scanling);
        }

        if batch.len() == batch.capacity() || (!batch.is_empty() && last_flush.elapsed() >= shared.config.database.flush_interval) {
            if let Err(err) = database.write_many(&batch).await {
                error!("error writing to database: {:?}", err);
            } else {
                info!("wrote {} to database", batch.len());
            }

            last_flush = Instant::now();
            batch.clear();
        }

        adapter.expire_timeouts();

        if done.load(Ordering::Acquire) {
            break;
        }
    }

    while let Some(scanling) = queue.pop() {
        batch.push(scanling);
    }

    if let Err(err) = database.write_many(&batch).await {
        error!("error writing to database: {:?}", err);
    } else {
        info!("wrote {} to database", batch.len());
    }
}

fn spawn_saturator<'umem: 'b, 'b, A: Adapter, P: Parser>(
    mut scanner: Scanner<'umem, 'b, A>,
    mut responder: Responder<'umem, 'b, A, impl Payload, P>,
    mut completer: Completer,
    done: &'b AtomicBool,
    queue: &'b SegQueue<Scanling<P>>
) -> (Sender<'umem>, DestructedResponder<'umem>) {
    loop {
        if let Some(error) = scanner.tick(&mut completer) {
            error!("{error:?}");
        }

        let result = responder.tick(&mut completer);
        if let Err(err) = result {
            error!("failed to tick receiver: {}", err);
        }

        for scanling in responder.scanlings.drain(..) {
            queue.push(scanling);
        }

        completer.tick();

        if done.load(Ordering::Acquire) {
            break
        }
    }

    let (receiver, sender) = responder.into_inner();
    (scanner.into_inner(), (receiver, sender, completer.into_inner()))
}
