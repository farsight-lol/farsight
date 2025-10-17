use std::net::Ipv4Addr;
use anyhow::bail;
use crate::controller::strategy::Strategy;
use crate::net::range::{Ipv4Ranges, Ranges};

#[derive(Debug)]
pub struct SlashN(Ipv4Addr, u8);

impl SlashN {
    #[inline]
    pub fn new(ip: Ipv4Addr, block: u8) -> Self {
        Self(ip, block)
    } 
}

impl Strategy for SlashN {
    type Output = Ipv4Addr;

    #[inline]
    fn generate_ranges(&self) -> anyhow::Result<Ipv4Ranges> {
        if self.1 > 32 {
            bail!("cidr block out of range")
        }

        let ip_u32 = u32::from(self.0);
        let mask = if self.1 == 0 {
            0
        } else {
            !0u32 << (32 - self.1)
        };

        Ok((Ipv4Addr::from(ip_u32 & mask)..Ipv4Addr::from(ip_u32 | !mask)).into())
    }
}

