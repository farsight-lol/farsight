use crate::net::mac::MacAddr;
use std::{
    net::Ipv4Addr,
    ops::Deref,
    sync::{
        Arc,
    },
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
        config: Config,
    ) -> Self {
        Self(Arc::new(InnerSharedData {
            source_ip,
            gateway,
            interface,
            config,
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
    pub config: Config,
}
