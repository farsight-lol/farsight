use std::net::Ipv4Addr;
use crate::database::Database;
use crate::net::range::Ipv4Ranges;

pub trait Selector {
    async fn select(&self, database: &mut Database) -> anyhow::Result<Ipv4Ranges>;
}

pub struct AllSelector;
impl Selector for AllSelector {
    #[inline(always)]
    async fn select(&self, _database: &mut Database) -> anyhow::Result<Ipv4Ranges> {
        Ok((Ipv4Addr::UNSPECIFIED..=Ipv4Addr::BROADCAST).into())
    }
}

#[derive(Clone)]
pub struct RescanSelector {
    count: usize
}

impl RescanSelector {
    #[inline]
    pub const fn new(count: usize) -> Self {
        Self { count }
    }
}

impl Selector for RescanSelector {
    #[inline]
    async fn select(&self, database: &mut Database) -> anyhow::Result<Ipv4Ranges> {
        let ranges = database.read_ranges(self.count).await?;
        
        Ok(ranges.into())
    }
}
