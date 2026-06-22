mod completer;
mod printer;
mod receiver;
mod responder;
mod scanner;
mod sender;

pub mod shared;
pub mod strategy;
pub mod protocol;
pub mod session;

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
use anyhow::{anyhow, bail, Context};
use aya::{maps::XskMap, programs::Xdp, Ebpf};
use log::{debug, error, info, warn};
use rand::random;
use serde::Serialize;
use std::{cell::RefCell, hint, marker::PhantomData, mem, ops::{DerefMut, RangeInclusive}, ptr, sync::{
    atomic::{AtomicBool, Ordering}, mpsc,
    Arc,
    Mutex,
}, thread, thread::{Builder, JoinHandle, Scope}, time::{Duration, Instant}};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::rc::Rc;
use std::sync::atomic::AtomicUsize;
use std::sync::RwLock;
use crossbeam_queue::SegQueue;
use crate::config::{Config, PingConfig, StrategyConfig};
use crate::controller::printer::Printer;
use crate::controller::strategy::adapter::{Adapter};
use crate::controller::strategy::selector::Selector;
use crate::net::range::Ipv4Ranges;
use crate::xdp::ring::Consumer;
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

pub(in crate::controller) type DestructedResponder<'umem> = (Receiver<'umem>, Sender<'umem>, Consumer<u64>);

pub struct Controller<'umem> {
    // we have to own it because if we drop it the xdp program
    // gets unloaded
    _ebpf: Ebpf,

    pub(in crate::controller) shared: SharedData,

    pub(in crate::controller) saturators: Vec<(Sender<'umem>, DestructedResponder<'umem>)>,
    pub database: Database,
}

impl<'umem> Controller<'umem> {
    #[inline]
    pub async fn new(
        mut ebpf: Ebpf,
        umems: &'umem [Umem],
        config: Config
    ) -> Result<Self, anyhow::Error> {
        debug!("attaching to interface '{}'", config.controller.interface);

        let interface_index = interface::name_to_index(
            &config.controller.interface,
        )
        .context("getting interface index from name - maybe it's wrong?")?;

        debug!("interface index = {interface_index}");

        let gateway_mac = gateway::get_mac(interface_index)
            .await
            .context("getting gateway mac")?;

        debug!("gateway mac = {gateway_mac:02X?}");

        let interface_mac = interface::get_mac(&config.controller.interface)
            .context("getting interface mac")?;

        debug!("interface mac = {interface_mac:02X?}");

        let source_ip = ip::get_local_ip(&config.controller.interface)
            .context("getting local ip")?;

        debug!("source ip = {source_ip:?}");

        let xdp_program: &mut Xdp =
            ebpf.program_mut("farsight_xdp").unwrap().try_into()?;
        xdp_program.load()?;
        xdp_program.attach_to_if_index(interface_index, config.xdp.attach_mode.to_flags())
            .context("attaching the XDP program - XDP is unsupported for your network driver. try experimenting with the xdp.mode and xdp.attach_mode options.")?;

        let flags = BindFlags::NeedWakeup | config.xdp.mode.to_flags();

        let usable_queue_count = umems.len();
        let shared = SharedData::new(
            source_ip,
            gateway_mac,
            interface_mac,
            config.controller.max_rate as f64 / usable_queue_count as f64,
            config,
        );

        let database = Database::new(shared.clone())
            .await
            .context("creating database")?;

        // we give each socket its own umem to avoid collision errors,
        // and it's overall better for concurrency
        // wastes a bit of memory tho

        let mut saturators = Vec::with_capacity(usable_queue_count);

        let mut socks = XskMap::try_from(ebpf.map_mut("SOCKS").unwrap())?;
        for queue_id in 0..usable_queue_count as u32 {
            let umem = &umems[queue_id as usize];

            let socket = Socket::new().context("initializing socket")?;
            umem.bind(socket.clone())?;

            let (tx, fr, rx, cr) = {
                let allocator =
                    socket.rings().context("initializing ring allocator")?;

                (
                    allocator.tx(shared.config.xdp.ring_size).context("initializing tx ring")?,
                    allocator.fr(shared.config.xdp.ring_size).context("initializing fr ring")?,
                    allocator.rx(shared.config.xdp.ring_size).context("initializing rx ring")?,
                    allocator.cr(shared.config.xdp.ring_size).context("initializing cr ring")?,
                )
            };

            socket
                .bind(flags.clone(), interface_index, queue_id, 0)
                .context("binding socket")?;

            socks
                .set(queue_id, socket.clone(), 0)
                .context("setting socket fd")?;

            let sender = Sender::new(
                shared.clone(),
                umem,
                socket.clone(),
                tx,
                0
            ).context("initializing sender")?;

            let socket_shared = Socket::new().context("initializing socket")?;

            let tx = {
                let allocator =
                    socket_shared.rings().context("initializing ring allocator")?;

                allocator.tx(shared.config.xdp.ring_size).context("initializing tx ring")?
            };

            socket_shared
                .bind(BindFlags::SharedUmem, interface_index, queue_id, socket.as_raw_fd() as u32)
                .context("binding socket")?;

            saturators.push((
                sender,
                (
                    Receiver::new(
                        umem,
                        socket.clone(),
                        fr,
                        rx,
                        shared.config.xdp.ring_size,
                    ).context("initializing receiver")?,
                    Sender::new(
                        shared.clone(),
                        umem,
                        socket_shared.clone(),
                        tx,
                        2 * shared.config.xdp.ring_size
                    ).context("initializing sender")?,
                    cr
                )
            ));
        }

        Ok(Self {
            _ebpf: ebpf,

            database,

            shared,

            saturators
        })
    }

    #[inline]
    pub async fn session<A: Adapter>(
        &'_ mut self,
        seed_ports: &[u16],
        excludes: &'_ Ipv4Ranges,
        selector: impl Selector,
    ) -> anyhow::Result<Session<'umem, '_, A>> {
        let mut ranges = selector.select(
            &mut self.database
        ).await.context("selecting ranges")?;

        ranges.exclude(excludes);

        Session::new(
            self.shared.clone(),
            &mut self.database,
            &mut self.saturators,
            ranges.compile(),
            seed_ports
        ).await
    }
}
