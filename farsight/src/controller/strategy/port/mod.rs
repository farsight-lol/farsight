pub mod pmap;

use std::net::Ipv4Addr;
use std::time::Instant;
use crate::controller::shared::SharedData;
use crate::database::Database;

pub trait PortExpirer {
    fn expire(&mut self, now: Instant, batch_size: usize);
}

pub trait PortAdapter: Send + Sync {
    async fn new(
        shared: SharedData,
        database: &mut Database,
        seed_ports: &[u16]
    ) -> anyhow::Result<Self> where Self: Sized;

    fn enqueue(&self, addr: Ipv4Addr, now: Instant, rng: &mut impl rand::Rng);

    fn on_result(&self, addr: Ipv4Addr, port: u16, hash: Option<u64>, rng: &mut impl rand::Rng);

    fn create_expirer(&self) -> impl PortExpirer;

    fn length(&self) -> usize;

    fn capacity(&self) -> usize;

    fn recv_into(&self, vec: &mut Vec<(u16, Ipv4Addr, u16)>, batch_size: usize);

    #[inline]
    fn at_capacity(&self) -> bool {
        self.length() >= self.capacity()
    }
}