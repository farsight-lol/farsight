use std::net::Ipv4Addr;
use anyhow::bail;
use rand::{random, random_range};
use crate::controller::strategy::{CombinedStrategy, Strategy, StrategyTransformer};
use crate::controller::strategy::ip::slashn::SlashN;
use crate::controller::strategy::port::allnp::AllPortsNonPrivileged;
use crate::controller::strategy::port::range::RangedPorts;
use crate::database::Database;
use crate::net::range::Address;

// the approach we're taking is the
// epsilon-greedy strategy
pub struct StrategySelector<'a> {
    database: &'a Database,

    epsilon: f64
}

impl<'a> StrategySelector<'a> {
    #[inline]
    pub fn new(database: &'a Database, epsilon: f64) -> anyhow::Result<Self> {
        if !(0f64..=1f64).contains(&epsilon) {
            bail!("epsilon out of bounds")
        }

        Ok(Self {
            database,
            epsilon
        })
    }

    #[inline]
    pub fn select(&self) -> Box<dyn Strategy<Output=Address>> {
        if random_range(0f64..=1f64) > self.epsilon {
            self.select_exploit()
        } else {
            self.select_explore()
        }
    }
    
    #[inline]
    fn select_exploit(&self) -> Box<dyn Strategy<Output=Address>> {
        let ip_strategy = SlashN::new(Ipv4Addr::new(0, 0, 0, 0), 0);
        let port_strategy = AllPortsNonPrivileged;

        Box::new(ip_strategy.combine_with(port_strategy))
    }

    #[inline]
    fn select_explore(&self) -> Box<dyn Strategy<Output=Address>> {
        // no data is exploited, only random ports & ip's are searched
        
        let ip_strategy = SlashN::new(
            Ipv4Addr::from_bits(random()),
            random_range(0..=32)
        );
        
        let port_start = random_range(1024..=65535);
        let port_end = random_range(port_start..=65535);
        
        let port_strategy = RangedPorts::new(port_start, port_end);
        
        Box::new(ip_strategy.combine_with(port_strategy))
    }
}
