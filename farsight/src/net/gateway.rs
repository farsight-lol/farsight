use crate::net::{ip, mac::MacAddr};
use anyhow::{bail, Context};
use std::{fs::read_to_string, net::Ipv4Addr, str::FromStr};

pub fn get_ipv4(iface: &str) -> Result<Ipv4Addr, anyhow::Error> {
    let route_data =
        read_to_string("/proc/net/route").context("reading route data")?;

    for row in route_data.trim().split("\n") {
        let fields: Vec<&str> = row.split("\t").collect();
        if fields.len() < 3 || fields[2] == "00000000" || fields[0] != iface {
            continue;
        }

        return ip::parse(fields[2]).context("parsing ipv4");
    }

    bail!("failed to get ip from interface name - maybe it's wrong?")
}

pub fn get_mac(ip: &Ipv4Addr) -> Result<MacAddr, anyhow::Error> {
    let arp_data =
        read_to_string("/proc/net/arp").context("reading arp data")?;

    for row in arp_data.trim().split("\n") {
        let fields: Vec<&str> =
            row.split(" ").filter(|val| !val.is_empty()).collect();

        if fields.len() < 6 {
            continue;
        }

        let arp_ip = Ipv4Addr::from_str(fields[0]);
        let Ok(arp_ip) = arp_ip else { continue };
        if arp_ip.ne(ip) {
            continue;
        }

        return fields[3].try_into().context("parsing mac");
    }

    bail!("failed to get mac from interface name - maybe it's wrong?")
}
