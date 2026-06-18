use crate::{
    controller::strategy::{
        ip::range::RangedIps, Strategy,
        StrategyTransformer,
    },
    database::Database,
    net::range::Address,
};
use rand::{random_range};
use std::net::Ipv4Addr;
use crate::controller::strategy::port::one::OnePort;

// the approach we're taking is the
// epsilon-greedy strategy
pub struct StrategySelector<'a> {
    database: &'a Database,

    epsilon: f64,
}

impl<'a> StrategySelector<'a> {
    #[inline]
    pub fn new(database: &'a Database) -> anyhow::Result<Self> {
        Ok(Self {
            database,
            epsilon: 1.0, // todo: load from file
        })
    }

    #[inline]
    pub fn select(&self) -> Box<dyn Strategy<Output = Address>> {
        if random_range(0f64..=1f64) <= self.epsilon {
            self.select_explore()
        } else {
            self.select_exploit()
        }
    }

    #[inline]
    fn select_exploit(&self) -> Box<dyn Strategy<Output = Address>> {
        unimplemented!()
    }

    #[inline]
    fn select_explore(&self) -> Box<dyn Strategy<Output = Address>> {
        let ip_strategy = RangedIps::new_cidr(Ipv4Addr::UNSPECIFIED, 0);
        let port_strategy = OnePort::new(25565);

        Box::new(ip_strategy.combine_with(port_strategy))
    }
}
