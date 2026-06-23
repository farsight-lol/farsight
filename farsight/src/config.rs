use crate::xdp::socket::BindFlags;
use anyhow::Context;
use aya::programs::XdpFlags;
use serde::Deserialize;
use serde_with::{serde_as, DurationSeconds};
use std::{fs::read_to_string, time::Duration};
use rand::RngExt;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub controller: ControllerConfig,
    pub database: DatabaseConfig,
    pub strategy: StrategyConfig,
    pub session: SessionConfig,
    pub ping: PingConfig,
    pub xdp: XdpConfig,
    pub tcp: TcpConfig,
}

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct ControllerConfig {
    pub source_port: PortRange,
    pub interface: String,

    #[serde_as(as = "DurationSeconds<u64>")]
    pub print_every: Duration
}

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub user: String,
    pub password: String,
    pub database: String,
    pub table: String,

    #[serde_as(as = "DurationSeconds<u64>")]
    pub flush_interval: Duration,
    pub flush_capacity: usize
}

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct StrategyConfig {
    pub max_rate: f64,
    
    pub budget_per_address: u32,
    pub epsilon: EpsilonConfig,
    
    pub catchall_threshold: u8,
    
    #[serde_as(as = "DurationSeconds<u64>")]
    pub timeout: Duration,
    pub seed_ports: Vec<PortRange>
}

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct EpsilonConfig {
    pub ip: f64,
    pub port: f64,
}

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct SessionConfig {
    #[serde_as(as = "DurationSeconds<u64>")]
    pub duration: Duration,

    pub rescan: RescanConfig
}

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct RescanConfig {
    pub max_count: usize,
    pub epsilon: f64,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(untagged)]
pub enum PortRange {
    Range([u16; 2]),
    Single(u16)
}

impl PortRange {
    #[inline]
    pub fn as_vec(&self) -> Vec<u16> {
        match self {
            PortRange::Range([start, end]) => (*start..=*end).into_iter().collect(),
            PortRange::Single(port) => vec![*port]
        }
    }

    #[inline]
    pub fn sample(&self, rand: &mut impl rand::Rng) -> u16 {
        match *self {
            PortRange::Range([start, end]) => rand.random_range(start..=end),
            PortRange::Single(port) => port
        }
    }

    #[inline]
    pub const fn start(&self) -> u16 {
        match self {
            PortRange::Range([start, _]) => *start,
            PortRange::Single(port) => *port
        }
    }

    #[inline]
    pub const fn end(&self) -> u16 {
        match self {
            PortRange::Range([_, end]) => *end,
            PortRange::Single(port) => *port
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct PingConfig {
    pub host: String,
    pub port: u16,
    pub protocol_version: i32,
}

#[derive(Debug, Deserialize)]
pub struct TcpConfig {
    pub max_reorder_segments: usize,
    pub max_reorder_bytes: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(PartialEq)]
pub enum XdpMode {
    Copy,
    ZeroCopy,
    Fallback,
}

impl XdpMode {
    #[inline]
    pub const fn to_flags(&self) -> BindFlags {
        match self {
            XdpMode::Copy => BindFlags::Copy,
            XdpMode::ZeroCopy => BindFlags::ZeroCopy,
            XdpMode::Fallback => BindFlags::empty(),
        }
    }
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum XdpAttachMode {
    Driver,
    Hardware,
    Skb,
}

impl XdpAttachMode {
    #[inline]
    pub const fn to_flags(&self) -> XdpFlags {
        match self {
            XdpAttachMode::Driver => XdpFlags::DRV_MODE,
            XdpAttachMode::Hardware => XdpFlags::HW_MODE,
            XdpAttachMode::Skb => XdpFlags::SKB_MODE,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct XdpConfig {
    pub mode: XdpMode,
    pub attach_mode: XdpAttachMode,
    pub checksum_offload: bool,

    pub ring_size: u32,
}

pub fn load(filename: &str) -> Result<Config, anyhow::Error> {
    let content = read_to_string(filename).context("reading file")?;

    toml::from_str(&content).context("parsing config")
}
