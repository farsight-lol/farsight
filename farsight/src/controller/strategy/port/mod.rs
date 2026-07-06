pub mod pmap;

use std::net::Ipv4Addr;
use std::time::Instant;
use crossbeam_epoch::Guard;
use crate::controller::sender::PacketTemplate;
use crate::controller::shared::SharedData;
use crate::database::Database;

pub trait PortExpirer: Send {
    fn expire(&mut self, now: Instant, guard: &Guard);
}

pub trait PortGenerationGuard {
    fn generate(self, addr: Ipv4Addr, now: Instant, rng: &mut impl rand::Rng, guard: &Guard) -> PacketTemplate;
}

pub trait PortGenerator {
    fn guard(&self) -> Option<impl PortGenerationGuard>;
}

pub trait PortGuard {
    fn generator(&self) -> impl PortGenerator;
    fn expirer(&self, batch_size: usize) -> impl PortExpirer;
}

pub trait PortAdapter: Send + Sync {
    async fn new(
        shared: SharedData,
        database: &mut Database,
        seed_ports: &[u16]
    ) -> anyhow::Result<Self> where Self: Sized;

    fn on_result(&self, addr: Ipv4Addr, port: u16, hash: Option<u64>, rng: &mut impl rand::Rng) -> Option<PacketTemplate>;

    fn guard(&self) -> impl PortGuard;
}
