use crate::controller::strategy::Strategy;
use crate::net::range::Ranges;

#[derive(Debug)]
pub struct OnePort(u16);

impl OnePort {
    #[inline]
    pub const fn new(port: u16) -> Self {
        Self(port)
    }
}

impl Strategy for OnePort {
    type Output = u16;

    #[inline]
    fn generate_ranges(&self) -> anyhow::Result<Ranges<Self::Output>> {
        Ok((self.0..self.0).into())
    }
}