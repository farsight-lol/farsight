use std::net::Ipv4Addr;
use crate::controller::strategy::Strategy;
use crate::net::range::Ipv4Ranges;

#[derive(Debug)]
pub struct OneIp(Ipv4Addr);

impl OneIp {
    #[inline]
    pub fn new(ip: Ipv4Addr) -> Self {
        Self(ip)
    }
}

impl Strategy for OneIp {
    type Output = Ipv4Addr;

    #[inline]
    fn generate_ranges(&self) -> anyhow::Result<Ipv4Ranges> {
        Ok((self.0..=self.0).into())
    }
}