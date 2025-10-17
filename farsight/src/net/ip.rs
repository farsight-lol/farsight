use crate::net::interface::IfAddrs;
use anyhow::{bail, Context};
use std::net::Ipv4Addr;

pub fn get_local_ip(iface: &str) -> Result<Ipv4Addr, anyhow::Error> {
    let ifaddrs = IfAddrs::new().context("getting ifaddrs")?;

    for ifaddr in ifaddrs {
        if ifaddr.addr.is_none() || ifaddr.name != iface {
            continue;
        }

        return Ok(ifaddr.addr.unwrap());
    }

    bail!("could not find local ip from interface");
}

pub fn parse(s: &str) -> Result<Ipv4Addr, anyhow::Error> {
    if s.len() != 8 {
        bail!("invalid ip length: expected 8 but got {}", s.len())
    }

    let o1 = u8::from_str_radix(&s[6..8], 16)?;
    let o2 = u8::from_str_radix(&s[4..6], 16)?;
    let o3 = u8::from_str_radix(&s[2..4], 16)?;
    let o4 = u8::from_str_radix(&s[0..2], 16)?;

    Ok(Ipv4Addr::new(o1, o2, o3, o4))
}
