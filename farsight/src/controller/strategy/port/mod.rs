pub mod pmap;

use std::net::Ipv4Addr;
use crate::controller::shared::SharedData;
use crate::database::Database;

pub trait PortAdapter: Send + Sync {
    async fn new(
        shared: SharedData,
        database: &mut Database,
        seed_ports: &[u16]
    ) -> anyhow::Result<Self> where Self: Sized;
    
    fn enqueue_address(&self, addr: Ipv4Addr, rng: &mut impl rand::Rng);

    fn on_result<const OPEN: bool>(&self, addr: Ipv4Addr, port: u16, rng: &mut impl rand::Rng);

    fn expire_timeouts(&self);

    fn is_at_capacity(&self) -> bool;

    fn pop(&self) -> Option<(u16, Ipv4Addr, u16)>;
}