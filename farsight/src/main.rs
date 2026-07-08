#![feature(ip_as_octets, adt_const_params, const_param_ty_trait, min_adt_const_params, likely_unlikely)]

extern crate core;

mod controller;
mod config;
mod database;
mod exclude;
mod net;
mod xdp;

use std::collections::HashSet;
use crate::controller::{
    Controller,
};
use anyhow::{bail, Context};
use aya::{
    Btf,
    EbpfLoader,
};
use aya_log::EbpfLogger;
use controller::protocol::minecraft::{build_latest_request, SLPParser};
use std::io::Error;
use std::thread;
use futures::executor::block_on;
use log::{debug, error, info, trace, warn};
use rand::{random, RngExt, SeedableRng};
use rand_xoshiro::Xoshiro256Plus;
use crate::controller::strategy::ip::pmap::PmapIpAdapter;
use crate::controller::strategy::port::pmap::PmapPortAdapter;
use crate::controller::strategy::selector::{AllSelector, RescanSelector, Selector};
use crate::net::nic::InterfaceInfoGuard;
use crate::xdp::umem::Umem;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    set_resource_limit().context("setting resource limit")?;

    let config = config::load("config.toml")
        .context("loading config file, maybe you forgot to copy `config.example.toml` into `config.toml`?")?;
    let excludes =
        exclude::load("exclude.conf").context("loading exclude file")?;

    let queues = {
        let mut guard =
            InterfaceInfoGuard::new(&config.controller.interface)
                .context("initializing interface guard")?;

        guard.queues().context("getting interface queues")?
    };

    debug!("queues = {queues:?}");

    let queue_count = queues.current.combined;
    let parallelism = thread::available_parallelism()
        .context("error getting available parallelism")?
        .get();

    if queue_count == 0 {
        let usable_queue_count = parallelism.saturating_sub(2)
            .max(1)
            .min(queues.max.combined as usize) as u32;

        bail!(
              "NIC reports 0 queues which means ; \
              consider 'ethtool -L {} combined {}' to fix",
              config.controller.interface, usable_queue_count
            );
    }

    let usable_queue_count = parallelism.saturating_sub(2)
        .max(1)
        .min(queue_count as usize) as u32;

    debug!("usable queue count = {}", usable_queue_count);
    if usable_queue_count < queue_count {
        bail!(
              "NIC reports {} queues but only using {} to leave cores free for management/db; \
              consider 'ethtool -L {} combined {}' to match",
              queues.max.combined, queues.current.combined, config.controller.interface, usable_queue_count
            );
    }

    let mut bpf = EbpfLoader::new()
        .btf(Btf::from_sys_fs().ok().as_ref())
        .set_global(
            "SOURCE_PORT_START",
            &config.controller.source_port.start(),
            true,
        )
        .set_global(
            "SOURCE_PORT_END",
            &config.controller.source_port.end(),
            true,
        )
        .set_global(
            "USABLE_QUEUES",
            &usable_queue_count,
            true,
        )
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/farsight-xdp"
        )))?;

    EbpfLogger::init(&mut bpf)?;

    let parser = SLPParser;
    let payload = build_latest_request(
        &config.ping.host,
        config.ping.port,
        config.ping.protocol_version,
    );

    let seed_ports = config.strategy.seed_ports.iter()
        .flat_map(|range| range.as_vec())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    // we give each socket its own umem to avoid collision errors,
    // and it's overall better for concurrency
    // wastes a bit of memory tho
    let umems = (0..usable_queue_count)
        .map(|_| Umem::new(
            2048,
            3 * config.xdp.ring_size,
            config.xdp.huge_pages
        ).context("creating umem"))
        .collect::<Result<Box<[_]>, _>>()?;

    let rescan_selector = RescanSelector::new(config.session.rescan.max_count);
    let epsilon = config.session.rescan.epsilon;
    let duration = config.session.duration;

    let mut controller = Controller::new(bpf, &umems, config)
        .await
        .context("creating controller")?;

    let mut rng = Xoshiro256Plus::from_seed(random());
    loop {
        let session = if rng.random_range(0f64..=1f64) >= epsilon {
            info!("scanning");

            controller.session::<PmapPortAdapter, PmapIpAdapter>(
                &excludes,
                AllSelector
            ).await
        } else {
            info!("rescanning");

            controller.session::<PmapPortAdapter, PmapIpAdapter>(
                &excludes,
                rescan_selector.clone()
            ).await
        };

        if let Err(err) = &session {
            error!("error while creating session: {err}");

            continue;
        }

        if let Err(err) = session.unwrap()
            .start(
                duration,
                &seed_ports,
                &payload,
                &parser
            )
            .await
        {
            error!("error while scanning: {err}");

            continue;
        };
    }
}

fn set_resource_limit() -> Result<(), Error> {
    cbail!(
        unsafe {
            libc::setrlimit(
                libc::RLIMIT_MEMLOCK,
                &libc::rlimit {
                    rlim_cur: libc::RLIM_INFINITY,
                    rlim_max: libc::RLIM_INFINITY,
                },
            )
        } < 0
    );

    Ok(())
}
