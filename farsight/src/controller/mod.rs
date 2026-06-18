mod completer;
mod printer;
pub mod protocol;
mod receiver;
mod responder;
mod scanner;
mod sender;
mod shared;

pub mod session;
pub mod strategy;

use crate::{
    config::{
        ControllerConfig, DatabaseConfig, XdpAttachMode, XdpConfig, XdpMode,
    },
    controller::{
        completer::Completer,
        protocol::{Parser, Payload},
        receiver::Receiver,
        responder::Responder,
        sender::Sender,
        session::Session,
        shared::SharedData,
    },
    database::{Database, Scanling},
    net::{
        gateway, interface, ip, nic::InterfaceInfoGuard, range::CompiledRanges,
    },
    xdp::umem::Umem,
};
use anyhow::Context;
use aya::{maps::XskMap, programs::Xdp, Ebpf};
use crossbeam_queue::SegQueue;
use log::{debug, error, info, warn};
use rand::random;
use serde::Serialize;
use std::{cell::RefCell, hint, marker::PhantomData, ops::{DerefMut, RangeInclusive}, ptr, sync::{
    atomic::{AtomicBool, Ordering}, mpsc,
    Arc,
    Mutex,
}, thread::{Builder, JoinHandle, Scope}, time::{Duration, Instant}};
use std::os::fd::AsRawFd;
use std::sync::atomic::AtomicUsize;
use crate::controller::printer::Printer;
use crate::xdp::socket::{BindFlags, Socket};

/// the caller must make sure that `dst` is valid for writes of at least `src.len() * size_of::<T>()` bytes
#[inline(always)]
pub const fn copy_from_slice_unchecked<T>(dst: *mut T, src: &[T]) {
    unsafe {
        ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
    }
}

/// the caller must make sure that `array.len()` is at least `N`
#[inline(always)]
pub const unsafe fn as_array_unchecked<T, const N: usize>(
    array: &[T],
) -> &[T; N] {
    unsafe { &*(array.as_ptr() as *const [T; N]) }
}

pub struct Controller {
    // we have to own it because if we drop it the xdp program
    // gets unloaded
    _ebpf: Ebpf,

    pub(in crate::controller) shared: SharedData,

    // todo: rethink this design here
    pub(in crate::controller) senders: SegQueue<Sender>,
    pub(in crate::controller) responders: SegQueue<(Receiver, Sender, Completer)>,
}

impl Controller {
    #[inline]
    pub async fn new(
        mut ebpf: Ebpf,
        controller_config: ControllerConfig,
        xdp_config: XdpConfig,
    ) -> Result<Self, anyhow::Error> {
        debug!("attaching to interface '{}'", controller_config.interface);

        let interface_index = interface::name_to_index(
            &controller_config.interface,
        )
        .context("getting interface index from name - maybe it's wrong?")?;

        debug!("interface index = {interface_index}");

        let gateway_mac = gateway::get_mac(interface_index)
            .await
            .context("getting gateway mac")?;

        debug!("gateway mac = {gateway_mac:02X?}");

        let interface_mac = interface::get_mac(&controller_config.interface)
            .context("getting interface mac")?;

        debug!("interface mac = {interface_mac:02X?}");

        let source_ip = ip::get_local_ip(&controller_config.interface)
            .context("getting local ip")?;

        debug!("source ip = {source_ip:?}");

        let queues = {
            let mut guard =
                InterfaceInfoGuard::new(&controller_config.interface)
                    .context("initializing interface guard")?;

            guard.queues().context("getting interface queues")?
        };

        debug!("queues = {queues:?}");

        let queue_count = queues.current.combined;
        if queues.max.combined > queue_count {
            warn!(
                "your current queue (channel) count on your nic is currently set to \
                {} which is lower than its max value. set it to max using \
                'ethtool -L {{interface}} combined {}' for better results",
                queue_count, queues.max.combined
            );
        }

        let xdp_program: &mut Xdp =
            ebpf.program_mut("farsight_xdp").unwrap().try_into()?;
        xdp_program.load()?;
        xdp_program.attach_to_if_index(interface_index, xdp_config.attach_mode.to_flags())
            .context("attaching the XDP program - XDP is unsupported for your network driver. try experimenting with the xdp.mode and xdp.attach_mode options.")?;

        let seed = random();
        debug!("seed = {seed}");

        let shared = SharedData::new(
            source_ip,
            gateway_mac,
            interface_mac,
            controller_config.source_port_range[0],
            controller_config.source_port_range[1],
            controller_config.print_every,
            seed,
            xdp_config.checksum_offload,
            xdp_config.ring_size,
            controller_config.max_rate
        );

        let senders = SegQueue::new();
        let responders = SegQueue::new();

        let flags = BindFlags::NeedWakeup | xdp_config.mode.to_flags();

        let mut socks = XskMap::try_from(ebpf.map_mut("SOCKS").unwrap())?;
        for queue_id in 0..queue_count {
            // we give each socket its own umem to avoid collision errors
            // and it's overall better for concurrency
            let umem = Arc::new(Umem::new(
                2048,
                3 * xdp_config.ring_size,
            ).context("creating umem")?);

            let socket = Socket::new().context("initializing socket")?;
            umem.bind(socket.clone())?;

            let (tx, fr, rx, cr) = {
                let allocator =
                    socket.rings().context("initializing ring allocator")?;

                (
                    allocator.tx(xdp_config.ring_size).context("initializing tx ring")?,
                    allocator.fr(xdp_config.ring_size).context("initializing fr ring")?,
                    allocator.rx(xdp_config.ring_size).context("initializing rx ring")?,
                    allocator.cr(xdp_config.ring_size).context("initializing cr ring")?,
                )
            };

            socket
                .bind(flags.clone(), interface_index, queue_id, 0)
                .context("binding socket")?;

            socks
                .set(queue_id, socket.clone(), 0)
                .context("setting socket fd")?;

            senders.push(Sender::new(
                shared.clone(),
                umem.clone(),
                socket.clone(),
                tx,
                0
            ).context("initializing sender")?);

            let socket_shared = Socket::new().context("initializing socket")?;

            let tx = {
                let allocator =
                    socket_shared.rings().context("initializing ring allocator")?;

                allocator.tx(xdp_config.ring_size).context("initializing tx ring")?
            };

            socket_shared
                .bind(BindFlags::SharedUmem, interface_index, queue_id, socket.as_raw_fd() as u32)
                .context("binding socket")?;

            responders.push((
                Receiver::new(
                    umem.clone(),
                    socket.clone(),
                    fr,
                    rx,
                    xdp_config.ring_size,
                ).context("initializing receiver")?,
                Sender::new(
                    shared.clone(),
                    umem,
                    socket_shared.clone(),
                    tx,
                    2 * xdp_config.ring_size
                ).context("initializing sender")?,
                Completer::new(cr)
            ));
        }

        Ok(Self {
            _ebpf: ebpf,

            shared,

            responders,
            senders,
        })
    }

    #[inline]
    pub fn guard<'scope, 'env: 'scope, PA: Payload, P: Parser>(
        &'env self,
        scope: &'scope Scope<'scope, 'env>,
        completed: &'env AtomicUsize,
        queue: &'env SegQueue<Scanling<P>>,
        database: &'env Database,
        payload: &'env PA,
        parser: &'env P,
        ping_timeout: &'env Duration,
    ) -> anyhow::Result<()> {
        loop {
            let Some((receiver, mut sender, mut completer)) = self.responders.pop() else {
                break;
            };

            let receiver = RefCell::new(receiver);

            scope.spawn(move || {
                let mut responder = Responder::new(
                    payload,
                    parser,
                    &mut sender,
                    &receiver,
                    *ping_timeout
                );

                loop {
                    let result = responder.tick();
                    if let Err(err) = result {
                        error!("failed to tick receiver: {}", err);
                    }

                    if let Some(count) = completer.tick() {
                        completed.fetch_add(
                            count.get(),
                            Ordering::Relaxed,
                        );
                    }

                    for scanling in responder.scanlings.drain(..) {
                        queue.push(scanling);
                    }
                }
            });
        }

        scope.spawn(|| {
            let mut printer = Printer::new(completed, self.shared.print_every);

            loop {
                printer.tick();

                let Some(banner) = queue.pop() else {
                    hint::spin_loop();

                    continue;
                };

                if let Err(e) = database.write(&banner) {
                    error!("failed to write to database: {e}");
                } else {
                    debug!("wrote 1 to database");
                }
            }
        });

        Ok(())
    }

    #[inline]
    pub fn session(
        &'_ self,
        ranges: CompiledRanges,
    ) -> Result<Session<'_>, anyhow::Error> {
        Session::new(
            self.shared.clone(),
            &self.senders,
            ranges,
        )
    }
}
