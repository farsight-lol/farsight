use crate::net::mac::MacAddr;
use std::{
    net::Ipv4Addr,
    ops::Deref,
    sync::{
        Arc,
    },
    time::Duration,
};
use crate::config::Config;

#[derive(Clone)]
pub struct SharedData(Arc<InnerSharedData>);

impl SharedData {
    #[inline]
    pub(super) fn new(
        source_ip: Ipv4Addr,
        gateway: MacAddr,
        interface: MacAddr,
        per_scanner_rate: f64,
        config: Config,
        seed: u64,
    ) -> Self {
        Self(Arc::new(InnerSharedData {
            source_ip,
            gateway,
            interface,
            per_scanner_rate,
            config,
            seed,
        }))
    }
}

impl Deref for SharedData {
    type Target = InnerSharedData;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

pub struct InnerSharedData {
    pub source_ip: Ipv4Addr,
    pub gateway: MacAddr,
    pub interface: MacAddr,
    pub per_scanner_rate: f64,
    pub config: Config,
    pub seed: u64,
}
