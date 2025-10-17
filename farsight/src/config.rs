use crate::xdp::socket::BindFlags;
use anyhow::Context;
use aya::programs::XdpFlags;
use serde::Deserialize;
use serde_with::{serde_as, DurationSeconds};
use std::{fs::read_to_string, time::Duration};
use std::collections::BTreeMap;
use enum_map::Enum;

#[derive(Deserialize)]
pub struct Config {
    pub controller: ControllerConfig,
    pub mongo: MongoConfig,
    pub strategy: StrategyConfig,
    pub session: SessionConfig,
    pub ping: PingConfig,
    pub xdp: XdpConfig,
}

#[serde_as]
#[derive(Deserialize)]
pub struct ControllerConfig {
    pub source_port_range: [u16; 2],
    pub interface: String,

    #[serde_as(as = "DurationSeconds<u64>")]
    pub print_every: Duration,
}

#[derive(Deserialize)]
pub struct MongoConfig {
    pub url: String,
    pub database: String,
    pub collections: Vec<CollectionConfig>
}

#[derive(Deserialize)]
pub struct StrategyConfig {
    pub epsilon: f64
}

#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Enum, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ParserKind {
    Slp
}

#[derive(Deserialize)]
pub struct CollectionConfig {
    pub parser: ParserKind,
    pub collection: String
}

#[serde_as]
#[derive(Deserialize)]
pub struct SessionConfig {
    #[serde_as(as = "DurationSeconds<u64>")]
    pub duration: Duration,
}

#[serde_as]
#[derive(Deserialize)]
pub struct PingConfig {
    #[serde_as(as = "DurationSeconds<u64>")]
    pub timeout: Duration,

    pub slp: SLPConfig,
}

#[derive(Deserialize)]
pub struct SLPConfig {
    pub host: String,
    pub port: u16,
    pub protocol_version: i32,
}

#[derive(Deserialize)]
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

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(PartialEq)]
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

#[derive(Deserialize)]
pub struct XdpConfig {
    pub mode: XdpMode,
    pub attach_mode: XdpAttachMode,

    pub ring_size: u32,
}

pub fn load(filename: &str) -> Result<Config, anyhow::Error> {
    let content = read_to_string(filename).context("reading file")?;

    toml::from_str(&content).context("parsing config")
}
