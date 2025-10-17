use crate::controller::strategy::Strategy;
use crate::net::range::Ranges;

#[derive(Default, Debug)]
pub struct RangedPorts(u16, u16);

impl RangedPorts {
    #[inline]
    pub const fn new(a: u16, b: u16) -> Self {
        Self(a, b)
    }
}

impl Strategy for RangedPorts {
    type Output = u16;

    #[inline]
    fn generate_ranges(&self) -> anyhow::Result<Ranges<Self::Output>> {
        Ok((self.0..self.1).into())
    }
}