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
use anyhow::Context;
use crossbeam_queue::{ArrayQueue, SegQueue};
use futures::executor::block_on;
use log::{debug, error, info};
use rand::{random, SeedableRng};
use tokio::runtime::{Builder, Handle, Runtime, TryCurrentError};
use crate::controller::DestructedResponder;
use crate::controller::feeder::Feeder;
use crate::controller::protocol::{Parser, Payload};
use crate::controller::receiver::Receiver;
use crate::controller::responder::Responder;
use crate::controller::strategy::ip::IpAdapter;
use crate::controller::strategy::port::{PortExpirer, PortAdapter};
use crate::database::{Database, Scanling};
use crate::xdp::ring::Consumer;

pub struct Session<'umem: 'b, 'b, A: PortAdapter, I: IpAdapter> {
    shared: SharedData,
    database: &'b mut Database,
    saturators: &'b mut Vec<(Sender<'umem>, DestructedResponder<'umem>)>,
    ranges: CompiledRanges,

    _phantom: PhantomData<(&'b A, &'b I)>,
}

impl<'umem: 'b, 'b, A: PortAdapter, I: IpAdapter> Session<'umem, 'b, A, I> {
    #[inline]
    pub(super) async fn new(
        shared: SharedData,
        database: &'b mut Database,
        saturators: &'b mut Vec<(Sender<'umem>, DestructedResponder<'umem>)>,
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
        let done = AtomicBool::new(false);

        let queue = ArrayQueue::new(self.shared.config.xdp.ring_size as usize);

        let seed = random();
        debug!("chosen seed for this session = {seed}");

        let port_adapter = A::new(
            self.shared.clone(),
            self.database,
            seed_ports
        ).await.context("creating port adapter")?;

        let ip_adapter = I::new(
            self.shared.clone(),
            self.database,
            self.ranges,
            seed
        ).await.context("creating ip adapter")?;

        thread::scope(|scope| {
            scope.spawn(|| {
                let future = spawn_printer_and_database(
                    self.shared.clone(),
                    self.database,
                    port_adapter.create_expirer(),
                    &done,
                    &completed,
                    &queue
                );

                Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(future)
            });

            let handles: Vec<_> = self.saturators.drain(..)
                .map(|(sender, (receiver, sender_responder, cr))|
                    scope.spawn(|| spawn_saturator(
                        Scanner::new(
                            sender,
                            &port_adapter,
                            seed
                        ),

                        Responder::new(
                            receiver,
                            sender_responder,
                            &port_adapter,
                            &ip_adapter,
                            payload,
                            parser,
                            seed
                        ),

                        Completer::new(
                            cr,
                            &completed
                        ),

                        &done,
                        &queue
                    ))
                ).collect();

            let mut feeder = Feeder::new(
                self.shared.clone(),
                seed,
                duration,
                &port_adapter,
                &ip_adapter
            );

            loop {
                if feeder.tick() {
                    break;
                }
            }

            debug!("finished session; waiting for threads to finish up...");

            thread::sleep(self.shared.config.strategy.timeout);
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
    done: &AtomicBool,
    completed: &AtomicUsize,
    queue: &ArrayQueue<Scanling<impl Parser + 'static>>
) {
    let flush_interval = shared.config.database.flush_interval;
    let flush_capacity = shared.config.database.flush_capacity;

    let mut batch = Vec::with_capacity(flush_capacity);

    let mut last_flush = Instant::now();
    let mut printer = Printer::new(completed, shared.config.controller.print_every);

    let mut cached_now = None;
    let mut ticks = 0u64;

    let mut write_task = None;

    loop {
        while let Some(scanling) = queue.pop() {
            debug!("HIT: {scanling:?}");

            batch.push(scanling);
        }

        if batch.len() == batch.capacity()
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

            let now = Instant::now();
            cached_now = Some(now);
            last_flush = now;
        }

        ticks = ticks.wrapping_add(1);
        if (ticks & 511) == 0 {
            let now = cached_now.take().unwrap_or_else(Instant::now);

            printer.tick(now);
            expirer.expire(now, 4096);
        }

        tokio::task::yield_now().await;

        if done.load(Ordering::Acquire) {
            break;
        }
    }

    if let Some(handle) = write_task.take() {
        let _ = handle.await;
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

fn spawn_saturator<'umem: 'b, 'b, A: PortAdapter, I: IpAdapter, P: Parser>(
    mut scanner: Scanner<'umem, 'b, A>,
    mut responder: Responder<'umem, 'b, A, I, impl Payload, P>,
    mut completer: Completer,
    done: &'b AtomicBool,
    queue: &'b ArrayQueue<Scanling<P>>
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
            queue.push(scanling).unwrap();
        }

        completer.tick();

        if done.load(Ordering::Acquire) {
            break
        }
    }

    let (receiver, sender) = responder.into_inner();
    (scanner.into_inner(), (receiver, sender, completer.into_inner()))
}
