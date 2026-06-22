pub mod pmap;

use std::net::Ipv4Addr;
use rand_xorshift::XorShiftRng;
use crate::controller::shared::SharedData;
use crate::database::Database;

pub trait Adapter: Send + Sync {
    async fn new(
        shared: SharedData,
        database: &mut Database,
        seed_ports: &[u16]
    ) -> anyhow::Result<Self> where Self: Sized;

    fn enqueue_address(&self, addr: Ipv4Addr, rng: &mut XorShiftRng);

    fn on_result<const OPEN: bool>(&self, addr: Ipv4Addr, port: u16, rng: &mut XorShiftRng);

    fn expire_timeouts(&self);

    fn is_at_capacity(&self) -> bool;

    fn pop(&self) -> Option<(u16, Ipv4Addr, u16)>;
}