#![feature(
    slice_index_methods,
    slice_ptr_get,
    ip_as_octets,
    ip_from,
    try_with_capacity,
    ptr_as_ref_unchecked,
    iter_array_chunks
)]
#![feature(iterator_try_collect)]
#![allow(unused_imports)]
extern crate core;

mod config;
mod controller;
mod database;
mod exclude;
mod net;
mod xdp;

use crate::{
    config::{XdpAttachMode, XdpMode},
    controller::{session::Session, strategy::Strategy, Controller},
    net::{
        interface, interface::IfAddrs, ip, nic::InterfaceInfoGuard,
        range::Ipv4Ranges,
    },
};
use anyhow::{bail, Context};
use aya::{
    maps::XskMap, programs::{SkMsg, Xdp, XdpFlags},
    Btf,
    EbpfLoader,
};
use aya_log::EbpfLogger;
use controller::protocol::minecraft::{build_latest_request, SLPParser};
use log::{debug, error, info, warn};
use net::gateway;
use std::{
    cell::{Cell, RefCell},
    io::Error,
    net::Ipv4Addr,
    sync::Arc,
    time::Duration,
};
use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::Builder;
use std::time::Instant;
use crossbeam_queue::SegQueue;
use tokio::runtime::Runtime;
use crate::controller::strategy::ip::slashn::SlashN;
use crate::controller::strategy::port::allnp::AllPortsNonPrivileged;
use crate::controller::strategy::selector::StrategySelector;
use crate::database::Database;

// stupid aya-rs requires tokio
// fuck you
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    set_resource_limit()
        .context("setting resource limit")?;

    let config = config::load("config.toml")
        .context("loading config file, maybe you forgot to copy `config.example.toml` into `config.toml`?")?;
    let excludes = exclude::load("exclude.conf")
        .context("loading exclude file")?;

    let mut bpf = EbpfLoader::new()
        .btf(Btf::from_sys_fs().ok().as_ref())
        .set_global(
            "SOURCE_PORT_START",
            &config.controller.source_port_range[0].to_be(),
            true,
        )
        .set_global(
            "SOURCE_PORT_END",
            &config.controller.source_port_range[1].to_be(),
            true,
        )
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/farsight-xdp"
        )))?;

    EbpfLogger::init(&mut bpf)?;

    let controller = Controller::new(
        bpf,
        config.controller,
        config.xdp
    ).context("creating controller")?;

    let payload = build_latest_request(
        &config.ping.slp.host,
        config.ping.slp.port,
        config.ping.slp.protocol_version,
    );

    let parser = SLPParser;

    let queue = SegQueue::new();
    let done = AtomicBool::new(false);
    let database = Database::new(config.mongo)
        .await
        .context("creating database")?;

    let strategy_selector = StrategySelector::new(&database, config.strategy.epsilon)
        .context("creating strategy selector")?;

    std::thread::scope(|scope| {
        controller.guard(
            scope,
            &done,
            &queue,
            &database,
            &payload,
            &parser,
            &config.ping.timeout,
        ).expect("guarding controller");
        
        // we gotta move it off-thread since we dont wanna interfere
        // with tokio
        // again, fuck you aya-rs
        scope.spawn(|| {
            loop {
                let mut ranges = {
                    let strategy = strategy_selector.select();

                    debug!("chosen strategy: {strategy:?}");

                    match strategy.generate_ranges() {
                        Ok(ranges) => ranges,

                        Err(err) => {
                            error!("error generating ranges, skipping: {err:?}");

                            continue
                        }
                    }
                };

                ranges.exclude(&excludes);

                let ranges = ranges.compile();

                debug!("scanning {} targets", ranges.count());

                let sesh = controller.session(
                    ranges
                ).expect("creating session");

                info!("starting session");

                sesh.start(config.session.duration);

                info!("exiting session");
            }

            done.store(true, Ordering::Release);
        });
        
        Ok(())
    })
}

fn set_resource_limit() -> Result<(), Error> {
    cbail!(unsafe {
        libc::setrlimit(
            libc::RLIMIT_MEMLOCK,
            &libc::rlimit {
                rlim_cur: libc::RLIM_INFINITY,
                rlim_max: libc::RLIM_INFINITY,
            },
        )
    } < 0);

    Ok(())
}
