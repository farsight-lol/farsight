use anyhow::bail;

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Default, Debug)]
pub struct MacAddr {
    octets: [u8; 6],
}

impl MacAddr {
    pub const UNSPECIFIED: MacAddr = MacAddr::from_octets([0; 6]);

    #[inline]
    pub const fn from_octets(octets: [u8; 6]) -> Self {
        Self { octets }
    }

    #[inline]
    pub const fn as_octets(&self) -> &[u8; 6] {
        &self.octets
    }

    pub fn from_str(s: &str) -> Result<MacAddr, anyhow::Error> {
        if s.len() != 17 {
            bail!("invalid MAC address length: {}", s.len());
        }

        let mut mac = [0u8; 6];
        for (i, o) in s.split(":").enumerate() {
            if i >= 6 {
                bail!("invalid MAC address segment count");
            }

            mac[i] = u8::from_str_radix(o, 16)?;
        }

        Ok(MacAddr::from_octets(mac))
    }
}

impl TryInto<MacAddr> for &str {
    type Error = anyhow::Error;

    #[inline]
    fn try_into(self) -> Result<MacAddr, Self::Error> {
        MacAddr::from_str(self)
    }
}
