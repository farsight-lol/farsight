pub mod pmap;

use std::net::Ipv4Addr;
use crate::controller::shared::SharedData;
use crate::database::Database;
use crate::net::range::CompiledRanges;

pub trait IpAdapter: Send + Sync {
    async fn new(
        shared: SharedData,
        database: &mut Database,
        ranges: CompiledRanges,
        seed: u64
    ) -> anyhow::Result<Self> where Self: Sized;

    fn next_address(&self, index: &mut u64, rng: &mut impl rand::Rng) -> Option<Ipv4Addr>;

    fn on_result(&self, addr: Ipv4Addr);
}