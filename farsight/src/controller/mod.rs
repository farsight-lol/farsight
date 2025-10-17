mod completer;
pub mod protocol;
mod receiver;
mod responder;
mod scanner;
mod sender;
pub mod session;
mod shared;
pub mod strategy;
mod xsk;
mod printer;

use crate::{
    config::{XdpAttachMode, XdpMode},
    controller::{
        completer::Completer,
        protocol::{Parser, Payload},
        receiver::Receiver,
        responder::Responder,
        sender::Sender,
        session::Session,
        shared::SharedData,
        xsk::Xsk,
    },
    net::{
        gateway, interface, ip, nic::InterfaceInfoGuard,
        range::CompiledRanges,
    },
    xdp::umem::Umem,
};
use anyhow::Context;
use aya::{
    maps::XskMap,
    programs::Xdp,
    Ebpf,
};
use log::{debug, error, warn};
use rand::random;
use std::{
    ops::RangeInclusive,
    ptr,
    sync::{
        atomic::{AtomicBool, Ordering}, Arc, Mutex
    },
    thread::{Builder},
    time::Duration,
};
use std::marker::PhantomData;
use std::ops::DerefMut;
use std::sync::mpsc;
use std::thread::{JoinHandle, Scope};
use std::time::Instant;
use crossbeam_queue::SegQueue;
use serde::Serialize;
use crate::config::{ControllerConfig, MongoConfig, XdpConfig};
use crate::database::{Database, Scanling};

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

    pub(in crate::controller) senders: SegQueue<Sender>,
    pub(in crate::controller) receivers: SegQueue<Receiver>,
    pub(in crate::controller) completers: SegQueue<Completer>,
}

impl Controller {
    #[inline]
    pub fn new(
        mut ebpf: Ebpf,
        controller_config: ControllerConfig,
        xdp_config: XdpConfig
    ) -> Result<Self, anyhow::Error> {
        debug!("attaching to interface '{}'", &controller_config.interface);

        let interface_index = interface::name_to_index(&controller_config.interface)
            .context("getting interface index from name - maybe it's wrong?")?;

        debug!("interface index = {interface_index}");

        // /proc/net/arp resets for some reason when i attach in DRV_MODE. weird.
        // so i just get the gateway mac before attaching
        let gateway_mac = gateway::get_mac(
            &gateway::get_ipv4(&controller_config.interface).context("getting gateway ip")?,
        )
        .context("getting gateway mac")?;

        debug!("gateway mac = {gateway_mac:02X?}");

        let interface_mac =
            interface::get_mac(&controller_config.interface).context("getting interface mac")?;

        debug!("interface mac = {interface_mac:02X?}");

        let source_ip =
            ip::get_local_ip(&controller_config.interface).context("getting local ip")?;

        debug!("source ip = {source_ip:?}");

        let queues = {
            let mut guard = InterfaceInfoGuard::new(&controller_config.interface)
                .context("initializing interface guard")?;

            guard.queues().context("getting interface queues")?
        };

        debug!("queues = {queues:?}");

        let queue_count = queues.current.combined;
        if queues.max.combined > queue_count {
            warn!(
                "your current queue (channel) count on your nic is currently set to \
                {} which is lower than its max value. set it to max using \
                'ethtool -L {{interface}} combined {}' to potentially increase performance",
                queue_count, queues.max.combined
            );
        }

        let xdp_program: &mut Xdp =
            ebpf.program_mut("farsight_xdp").unwrap().try_into()?;
        xdp_program.load()?;
        xdp_program.attach_to_if_index(interface_index, xdp_config.attach_mode.to_flags())
            .context("attaching the XDP program - XDP is unsupported for your network driver. try experimenting with the xdp.mode and xdp.attach_mode options.")?;

        let shared = SharedData::new(
            Umem::new(
                2048,
                // we multiply by 2 because there are 2 rings that use umem
                2 * queue_count * xdp_config.ring_size,
            )
            .context("creating umem")?,
            source_ip,
            gateway_mac,
            interface_mac,
            RangeInclusive::new(controller_config.source_port_range[0], controller_config.source_port_range[1]),
            controller_config.print_every,
            random(),
        );

        let mut senders = SegQueue::new();
        let mut completers = SegQueue::new();
        let mut receivers = SegQueue::new();

        let mut socks = XskMap::try_from(ebpf.map_mut("SOCKS").unwrap())?;
        let (socket, spewer, completer, receiver) =
            Xsk::Base(xdp_config.mode.to_flags())
                .create(
                    &mut socks,
                    shared.clone(),
                    interface_index,
                    0,
                    xdp_config.ring_size,
                )
                .context("creating socket")?;

        senders.push(spewer);
        completers.push(completer);
        receivers.push(receiver);

        // starting from 1 because 0 is the base socket
        for queue_id in 1..queue_count {
            let (socket, spewer, completer, receiver) =
                Xsk::Shared(socket.clone())
                    .create(
                        &mut socks,
                        shared.clone(),
                        interface_index,
                        queue_id,
                        xdp_config.ring_size,
                    )
                    .context(format!(
                        "creating shared full socket {queue_id}"
                    ))?;

            senders.push(spewer);
            completers.push(completer);
            receivers.push(receiver);

            let (_, spewer) = Xsk::Shared(socket.clone())
                .sender_only(
                    shared.clone(),
                    interface_index,
                    queue_id,
                    queue_count,
                    xdp_config.ring_size,
                )
                .context(format!("creating shared sender socket {queue_id}"))?;

            senders.push(spewer);
        }

        Ok(Self {
            _ebpf: ebpf,

            shared,

            receivers,
            senders,
            completers,
        })
    }

    #[inline]
    pub fn guard<'scope, 'env: 'scope, PA: Payload, P: Parser>(
        &'env self,
        scope: &'scope Scope<'scope, 'env>,
        done: &'env AtomicBool,
        queue: &'env SegQueue<Scanling<P>>,
        database: &'env Database,
        payload: &'env PA,
        parser: &'env P,
        ping_timeout: &'env Duration
    ) -> anyhow::Result<()> {
        loop {
            let Some(mut receiver) = self.receivers.pop() else {
                break;
            };

            let mut sender = self.senders.pop()
                .context("not enough senders")?;
            
            // probably dont have to explicitly define them like this
            // but this feels good
            let senders = &self.senders;
            let receivers = &self.receivers;

            scope.spawn(move || {
                let mut responder = Responder::new(
                    payload,
                    parser,
                    &mut sender,
                    &mut receiver,
                    *ping_timeout,
                );

                loop {
                    if done.load(Ordering::Acquire) {
                        break;
                    }

                    if let Some(banner) = responder.tick().expect("ticking responder") {
                        queue.push(banner);
                    }
                }

                senders.push(sender);
                receivers.push(receiver);
            });
        }

        scope.spawn(|| {
            let mut last_got = Instant::now();

            loop {
                let Some(banner) = queue.pop() else {
                    if last_got.elapsed().ge(ping_timeout) && done.load(Ordering::Acquire) {
                        break
                    }

                    continue
                };

                last_got = Instant::now();
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
            &self.completers,
            ranges,
        )
    }
}
