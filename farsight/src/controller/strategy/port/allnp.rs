use std::net::Ipv4Addr;
use crate::controller::strategy::Strategy;
use crate::net::range::Ranges;

#[derive(Default, Debug)]
pub struct AllPortsNonPrivileged;

impl Strategy for AllPortsNonPrivileged {
    type Output = u16;

    #[inline]
    fn generate_ranges(&self) -> anyhow::Result<Ranges<Self::Output>> {
        Ok((1024..65535).into())
    }
}