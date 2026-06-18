use crate::{
    controller::strategy::Strategy,
    net::range::Ipv4Ranges,
};
use std::net::Ipv4Addr;

#[derive(Debug)]
pub struct RangedIps(Ipv4Addr, Ipv4Addr);

impl RangedIps {
    #[inline]
    pub fn new_cidr(ip: Ipv4Addr, block: u8) -> Self {
        if block > 32 {
            panic!("cidr block out of range")
        }

        let ip = u32::from(ip);
        let mask = if block == 0 { 0 } else { !0u32 << (32 - block) };

        Self(Ipv4Addr::from(ip & mask), Ipv4Addr::from(ip | !mask))
    }
    
    #[inline]
    pub fn new(a: Ipv4Addr, b: Ipv4Addr) -> Self {
        Self(a, b)
    }
}

impl Strategy for RangedIps {
    type Output = Ipv4Addr;

    #[inline]
    fn generate_ranges(&self) -> anyhow::Result<Ipv4Ranges> {
        Ok((self.0..=self.1).into())
    }
}
