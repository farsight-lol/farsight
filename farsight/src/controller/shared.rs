use crate::net::mac::MacAddr;
use std::{
    net::Ipv4Addr,
    ops::Deref,
    sync::{
        atomic::AtomicIsize,
        Arc,
    },
    time::Duration,
};

#[derive(Clone)]
pub(super) struct SharedData(Arc<InnerSharedData>);

impl SharedData {
    #[inline]
    pub(super) fn new(
        source_ip: Ipv4Addr,
        gateway: MacAddr,
        interface: MacAddr,
        source_port_start: u16,
        source_port_end: u16,
        print_every: Duration,
        seed: u64,
        checksum_offload: bool,
        ring_size: u32,
        max_rate: u64
    ) -> Self {
        Self(Arc::new(InnerSharedData {
            source_ip,

            gateway,
            interface,

            source_port_start,
            source_port_end,

            reward: AtomicIsize::new(0),

            print_every,

            seed,

            checksum_offload,
            ring_size,
            
            max_rate
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
    pub(super) source_ip: Ipv4Addr,

    pub(super) gateway: MacAddr,
    pub(super) interface: MacAddr,

    pub(super) source_port_start: u16,
    pub(super) source_port_end: u16,

    pub(super) reward: AtomicIsize,

    pub(super) print_every: Duration,

    pub(super) seed: u64,
    
    pub(super) checksum_offload: bool,
    pub(super) ring_size: u32,
    
    pub(super) max_rate: u64,
}
