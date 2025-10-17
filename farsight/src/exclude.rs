use crate::net::range::Ipv4Ranges;
use anyhow::{bail, Context};
use std::{fs, net::Ipv4Addr, str::FromStr};

// thanks mat

#[inline]
pub fn load(input: &str) -> anyhow::Result<Ipv4Ranges> {
    let input = fs::read_to_string(input)
        .context("reading file")?;

    parse(&input)
        .context("parsing file")
}

fn parse(input: &str) -> anyhow::Result<Ipv4Ranges> {
    let mut ranges = Vec::new();

    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // can be either like 0.0.0.0-0.0.0.0 or 0.0.0.0/32
        let is_slash = line.contains('/');
        let is_hypen = line.contains('-');

        // remove everything after the first #
        let line = line.split('#').next().unwrap().trim();
        if is_slash && is_hypen {
            bail!("Invalid exclude range: {line} (cannot contain both - and /)")
        }

        let range = if is_slash {
            let mut parts = line.split('/');

            let ip = parts.next().unwrap();
            let mask = parts.next().unwrap();

            let mask = 32 - mask.parse::<u8>()?;
            let mask_bits = 2u32.pow(mask as u32) - 1;

            let ip_u32 = u32::from(Ipv4Addr::from_str(ip)?);

            Ipv4Addr::from(ip_u32 & !mask_bits)
                ..Ipv4Addr::from(ip_u32 | mask_bits)
        } else if is_hypen {
            let mut parts = line.split('-');

            let ip_start = parts.next().unwrap();
            let ip_end = parts.next().unwrap();

            let ip_start = Ipv4Addr::from_str(ip_start)?;
            let ip_end = Ipv4Addr::from_str(ip_end)?;

            if ip_start > ip_end {
                bail!(
                    "Invalid exclude range: {line} (start cannot be greater than end)",
                )
            }

            ip_start..ip_end
        } else {
            let ip = Ipv4Addr::from_str(line)?;

            ip..ip
        };

        ranges.push(range);
    }

    Ok(ranges.into())
}
