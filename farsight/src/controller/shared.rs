use crate::{net::mac::MacAddr, xdp::umem::Umem};
use std::{
    net::Ipv4Addr,
    ops::{Deref, RangeInclusive},
    sync::Arc,
};
use std::time::Duration;

#[derive(Clone)]
pub(super) struct SharedData(Arc<InnerSharedData>);

impl SharedData {
    #[inline]
    pub(super) fn new(
        umem: Umem,
        source_ip: Ipv4Addr,
        gateway: MacAddr,
        interface: MacAddr,
        source_port_range: RangeInclusive<u16>,
        print_every: Duration,
        seed: u64,
    ) -> Self {
        Self(Arc::new(InnerSharedData {
            umem,

            source_ip,

            gateway,
            interface,

            source_port_range,
            print_every,

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

pub(super) struct InnerSharedData {
    pub(super) umem: Umem,

    pub(super) source_ip: Ipv4Addr,

    pub(super) gateway: MacAddr,
    pub(super) interface: MacAddr,

    pub(super) source_port_range: RangeInclusive<u16>,

    pub(super) print_every: Duration,

    pub(super) seed: u64,
}
