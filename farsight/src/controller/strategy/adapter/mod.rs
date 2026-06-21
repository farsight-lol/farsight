pub mod session;

use std::net::Ipv4Addr;
use std::time::Instant;
use crossbeam_queue::SegQueue;
use dashmap::DashMap;
use rand_xorshift::XorShiftRng;
use crate::controller::shared::SharedData;
use crate::controller::strategy::graph::BannerCorrelationGraph;
use crate::database::Database;

pub trait Adapter: Send + Sync {
    async fn new(
        shared: SharedData,
        database: &mut Database,
        seed_ports: &[u16]
    ) -> anyhow::Result<Self> where Self: Sized;

    fn enqueue_address(&self, addr: Ipv4Addr, rng: &mut XorShiftRng);

    fn on_banner(&self, addr: Ipv4Addr, port: u16, rng: &mut XorShiftRng);
    fn on_empty(&self, addr: Ipv4Addr, port: u16, rng: &mut XorShiftRng);

    fn expire_timeouts(&self);

    fn pop(&self) -> Option<(u16, Ipv4Addr, u16)>;
}