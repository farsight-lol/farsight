use std::fmt::Debug;
use crate::{
    config::{DatabaseConfig},
    controller::{
        protocol::Parser,
        strategy::Strategy,
    },
};
use serde::Serialize;
use std::net::Ipv4Addr;
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize)]
pub struct Scanling<P: Parser> {
    timestamp: DateTime<Utc>,

    ip: Ipv4Addr,
    port: u16,

    response: P::Output,
}

impl<P: Parser> Scanling<P> {
    #[inline]
    pub fn new(ip: Ipv4Addr, port: u16, response: P::Output) -> Self {
        Self {
            timestamp: Utc::now(),
            ip,
            port,
            response,
        }
    }
}

pub struct Database {
}

impl Database {
    #[inline]
    pub async fn new(config: DatabaseConfig) -> anyhow::Result<Self> {
        Ok(Self {
        })
    }

    #[inline]
    pub fn write<P: Parser>(
        &'_ self,
        row: &Scanling<P>,
    ) -> anyhow::Result<()> {
        println!("FOUND: {row:?}");

        Ok(())
    }
}
