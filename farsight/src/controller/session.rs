use crate::controller::strategy::port::PortBatcher;
use crate::controller::strategy::port::{Expiry, PortGuard};
use crate::{
    controller::{
        completer::Completer, printer::Printer, scanner::Scanner,
        sender::Sender, shared::SharedData,
    },
    net::range::CompiledRanges,
};
use perfect_rand::PerfectRng;
use std::{mem, sync::atomic::{AtomicBool, AtomicUsize, Ordering}, thread, time::Duration};
use std::iter::zip;
use std::marker::PhantomData;
use std::ops::{Add, Sub};
use std::time::Instant;
use anyhow::{anyhow, bail, Context};
use core_affinity::CoreId;
use crossbeam_utils::Backoff;
use futures::executor::block_on;
use log::{debug, error, info};
use rand::{random, SeedableRng};
use tokio::runtime::{Builder, Handle, Runtime, TryCurrentError};
use tokio::{runtime, select};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::time::{interval, MissedTickBehavior};
use crate::controller::deque::worker::Worker;
use crate::controller::DestructedResponder;
use crate::controller::feeder::Feeder;
use crate::controller::protocol::{Parser, Payload};
use crate::controller::receiver::Receiver;
use crate::controller::responder::Responder;
use crate::controller::strategy::ip::IpAdapter;
use crate::controller::strategy::port::{PortExpirer, PortAdapter};
use crate::database::{Database, Scanling};
use crate::net::tcp::PacketTemplate;
use crate::xdp::ring::Consumer;

pub struct Session<'umem: 'env, 'env, A: PortAdapter, I: IpAdapter> {
    shared: SharedData,
    database: &'env mut Database,
    saturators: &'env mut Vec<(Sender<'umem>, DestructedResponder<'umem>)>,
    ranges: CompiledRanges,

    _phantom: PhantomData<(&'env A, &'env I)>,
}

impl<'umem: 'env, 'env, A: PortAdapter, I: IpAdapter> Session<'umem, 'env, A, I> {
    #[inline]
    pub(super) async fn new(
        shared: SharedData,
        database: &'env mut Database,
        saturators: &'env mut Vec<(Sender<'umem>, DestructedResponder<'umem>)>,
        ranges: CompiledRanges,
    ) -> Result<Self, anyhow::Error> {
        Ok(Self {
            database,
            shared,
            saturators,
            ranges,

            _phantom: PhantomData,
        })
    }

    #[inline]
    pub async fn start(
        self,
        duration: Duration,
        seed_ports: &[u16],
        payload: &impl Payload,
        parser: &(impl Parser + 'static)
    ) -> anyhow::Result<()> {
        info!("starting session");

        let completed = AtomicUsize::new(0);
        let filled = AtomicUsize::new(0);

        let done = AtomicBool::new(false);

        let (queue, receiver) = mpsc::unbounded_channel();

        let seed = random();
        debug!("chosen seed for this session = {seed}");

        let port_adapter = A::new(
            self.shared.clone(),
            self.database,
            seed_ports
        ).await.context("creating port adapter")?;

        let port_guard = port_adapter.guard();
        let port_expirer = port_guard.expirer(self.shared.config.strategy.timeout_batch);
        let port_generator = port_guard.generator();
        let port_batcher = port_guard.batcher();

        let ip_adapter = I::new(
            self.shared.clone(),
            self.database,
            self.ranges,
            seed
        ).await.context("creating ip adapter")?;

        let rate_per_completer = self.shared.config.controller.max_rate / self.saturators.len() as f64;

        thread::scope(|scope| {
            core_affinity::set_for_current(CoreId { id: 0 });

            scope.spawn(|| {
                core_affinity::set_for_current(CoreId { id: 1 });

                let future = spawn_printer_and_database(
                    self.shared.clone(),
                    self.database,
                    port_expirer,
                    &completed,
                    &filled,
                    receiver
                );

                Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(future)
            });

            let handles: Vec<_> = self.saturators.drain(..)
                .enumerate()
                .map(|(i, (sender, (receiver, sender_responder, cr)))| {
                    let shared = self.shared.clone();
                    let port_adapter = &port_adapter;
                    let ip_adapter = &ip_adapter;
                    let filled = &filled;
                    let completed = &completed;
                    let done = &done;

                    let stealer = port_batcher.stealer();
                    let queue = queue.clone();

                    scope.spawn(move || {
                        core_affinity::set_for_current(CoreId { id: i + 2 });

                        spawn_saturator(
                            Scanner::new(
                                sender,
                                seed,
                                stealer,
                            ),
                            Responder::new(
                                receiver,
                                sender_responder,
                                port_adapter,
                                ip_adapter,
                                payload,
                                parser,
                                filled,
                                seed,
                            ),
                            Completer::new(
                                shared,
                                cr,
                                rate_per_completer,
                                completed,
                            ),
                            done,
                            queue,
                        )
                    })
                }).collect();

            drop(queue);

            let mut feeder = Feeder::new(
                self.shared.clone(),
                seed,
                duration,
                port_batcher,
                port_generator,
                &ip_adapter
            );

            loop {
                if feeder.tick() {
                    break;
                }
            }

            debug!("finished session");

            done.store(true, Ordering::Release);
            for handle in handles {
                self.saturators.push(
                    handle.join().unwrap()
                );
            }
        });

        info!("exiting session");

        Ok(())
    }
}

async fn spawn_printer_and_database(
    shared: SharedData,
    database: &mut Database,
    mut expirer: impl PortExpirer,
    completed: &AtomicUsize,
    filled: &AtomicUsize,
    mut queue: UnboundedReceiver<Scanling<impl Parser + 'static>>
) {
    let flush_interval = shared.config.database.flush_interval;
    let flush_capacity = shared.config.database.flush_capacity;

    let mut batch = Vec::with_capacity(flush_capacity);

    let mut last_flush = Instant::now();
    let mut printer = Printer::new(
        completed,
        filled,
        shared.config.controller.print_every
    );

    let mut write_task = None;

    let mut housekeeping = interval(Duration::from_millis(1));
    housekeeping.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let guard = crossbeam_epoch::pin();

    loop {
        select! {
            received = queue.recv() => {
                match received {
                    Some(scanling) => {
                        debug!("HIT: {scanling:?}");

                        batch.push(scanling);
                        while let Ok(scanling) = queue.try_recv() {
                            batch.push(scanling);
                        };
                    }

                    None => break
                }
            }

            _ = housekeeping.tick() => {}
        }

        let now = Instant::now();
        printer.tick(now);
        expirer.expire(now, &guard);

        if batch.len() >= flush_capacity
            || (!batch.is_empty() && last_flush.elapsed() >= flush_interval)
        {
            if let Some(handle) = write_task.take() {
                let _ = handle.await;
            }

            let to_write = mem::replace(&mut batch, Vec::with_capacity(flush_capacity));
            let database = database.clone();

            write_task = Some(tokio::spawn(async move {
                if let Err(err) = database.write_many(&to_write).await {
                    error!("error writing to database: {:?}", err);
                } else {
                    info!("wrote {} to database", to_write.len());
                }
            }));

            last_flush = Instant::now();
        }
    }

    if let Some(handle) = write_task.take() {
        let _ = handle.await;
    }

    if batch.is_empty() {
        return;
    }

    if let Err(err) = database.write_many(&batch).await {
        error!("error writing to database: {:?}", err);
    } else {
        info!("wrote {} to database", batch.len());
    }
}

fn spawn_saturator<'umem: 'b, 'b, A: PortAdapter, I: IpAdapter, P: Parser>(
    mut scanner: Scanner<'umem, 'b>,
    mut responder: Responder<'umem, 'b, A, I, impl Payload, P>,
    mut completer: Completer,
    done: &'b AtomicBool,
    queue: UnboundedSender<Scanling<P>>
) -> (Sender<'umem>, DestructedResponder<'umem>) {
    let backoff = Backoff::new();
    loop {
        let mut progressed = false;

        match scanner.tick(&mut completer) {
            Some(error) => {
                error!("{error:?}");
            }
            None => progressed = true
        }

        let result = responder.tick(&mut completer);
        match result {
            Err(err) => {
                error!("failed to tick receiver: {}", err);
            }

            Ok(Some(())) => {
                progressed = true;
            }

            _ => {}
        }

        for scanling in responder.scanlings.drain(..) {
            _ = queue.send(scanling);
        }

        if completer.tick().is_some() {
            progressed = true;
        }

        if progressed { backoff.reset() } else { backoff.snooze() }

        if done.load(Ordering::Acquire) {
            break
        }
    }

    let (receiver, sender) = responder.into_inner();
    (scanner.into_inner(), (receiver, sender, completer.into_inner()))
}
