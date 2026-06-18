use anyhow::{bail, Context};
use std::{net::Ipv4Addr, str::FromStr};
use std::net::IpAddr;
use std::num::NonZeroU32;
use futures::TryStreamExt;
use rtnetlink::{new_connection, IpVersion, RouteMessageBuilder};
use rtnetlink::packet_route::neighbour::{NeighbourAddress, NeighbourAttribute};
use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute};
use surge_ping::{Client, Config, PingIdentifier, PingSequence};
use crate::net::mac::MacAddr;

pub async fn get_mac(interface_index: u32) -> Result<MacAddr, anyhow::Error> {
    let (connection, handle, _) = new_connection()
        .context("establishing netlink connection")?;
    let conn_task = tokio::spawn(connection);

    let result = inner(&handle, interface_index).await;

    drop(handle);
    conn_task.await?;

    result
}

async fn inner(handle: &rtnetlink::Handle, interface_index: u32) -> Result<MacAddr, anyhow::Error> {
    let gateway_ip = get_gateway_ip(handle, interface_index).await?;

    match get_mac_from_neigh(handle, gateway_ip).await {
        Ok(mac) => Ok(mac),
        Err(_) => {
            ping_gateway(gateway_ip, interface_index).await?;
            get_mac_from_neigh(handle, gateway_ip).await
        }
    }
}

async fn ping_gateway(gateway_ip: Ipv4Addr, interface_index: u32) -> Result<(), anyhow::Error> {
    let client = Client::new(&Config {
        interface_index: NonZeroU32::new(interface_index),
        ..Default::default()
    })?;
    
    let mut pinger = client
        .pinger(IpAddr::V4(gateway_ip), PingIdentifier(0))
        .await;

    pinger
        .ping(PingSequence(0), &[])
        .await
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("ping failed: {}", e))
}

async fn get_gateway_ip(
    handle: &rtnetlink::Handle,
    interface_index: u32,
) -> Result<Ipv4Addr, anyhow::Error> {
    let mut routes = handle.route().get(
        RouteMessageBuilder::<Ipv4Addr>::new()
            .table_id(0) // RT_TABLE_UNSPEC
            .build()
    ).execute();

    while let Some(route) = routes.try_next().await? {
        if route.header.destination_prefix_length != 0 {
            continue;
        }

        let via_iface = route.attributes.iter().find_map(|a| {
            if let RouteAttribute::Oif(idx) = a { Some(*idx) } else { None }
        });

        if !via_iface.is_some_and(|via_iface| via_iface == interface_index) {
            continue;
        }

        let gw = route.attributes.iter().find_map(|a| {
            if let RouteAttribute::Gateway(RouteAddress::Inet(addr)) = a {
                Some(addr)
            } else {
                None
            }
        });

        if let Some(ip) = gw {
            return Ok(*ip);
        }
    }

    bail!("no default gateway found for interface index {}", interface_index)
}

async fn get_mac_from_neigh(
    handle: &rtnetlink::Handle,
    gateway_ip: Ipv4Addr
) -> Result<MacAddr, anyhow::Error> {
    let mut neighs = handle
        .neighbours()
        .get()
        .set_family(IpVersion::V4)
        .execute();

    while let Some(neigh) = neighs.try_next().await? {
        let ip = neigh.attributes.iter().find_map(|a| {
            if let NeighbourAttribute::Destination(NeighbourAddress::Inet(addr)) = a {
                Some(addr)
            } else {
                None
            }
        });

        if !ip.is_some_and(|ip| gateway_ip.eq(ip)) {
            continue;
        }

        let mac = neigh.attributes.iter().find_map(|a| {
            if let NeighbourAttribute::LinkLayerAddress(bytes) = a {
                bytes.as_slice().try_into().ok()
            } else {
                None
            }
        });

        if let Some(m) = mac {
            return Ok(MacAddr::from_octets(m));
        }
    }

    bail!("gateway {} not in ARP cache", gateway_ip)
}
