use std::collections::HashMap;
use std::fmt::Debug;
use crate::{
    controller::{
        protocol::Parser,
    },
};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::ops::Deref;
use std::sync::Arc;
use anyhow::Context;
use chrono::{DateTime, Utc};
use clickhouse::{Client, Row};
use clickhouse::sql::Identifier;
use fxhash::FxHashSet;
use crate::controller::shared::SharedData;
use crate::controller::strategy::pmap::graph::BannerCorrelationGraph;

#[derive(Debug, Serialize, Deserialize, Row)]
pub struct Scanling<P: Parser> {
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    timestamp: DateTime<Utc>,

    #[serde(with = "clickhouse::serde::ipv4")]
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

#[derive(Clone)]
pub struct Database {
    shared: SharedData,
    inner: Arc<InnerDatabase>
}

pub struct InnerDatabase {
    client: Client
}

impl Deref for Database {
    type Target = InnerDatabase;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Database {
    #[inline]
    pub async fn new(shared: SharedData) -> anyhow::Result<Self> {
        let client = Client::default()
            .with_url(&shared.config.database.url)
            .with_user(&shared.config.database.user)
            .with_password(&shared.config.database.password)
            .with_database(&shared.config.database.database);

        Ok(Self {
            shared,
            inner: Arc::new(InnerDatabase {
                client
            })
        })
    }

    #[inline]
    pub async fn build_graph(&self, seed_ports: &[u16]) -> Result<BannerCorrelationGraph, anyhow::Error> {
        let table = &self.shared.config.database.table;
        let total: u64 = self.client
            .query("SELECT count(DISTINCT ip) FROM ?")
            .bind(table)
            .fetch_one()
            .await?;

        if total == 0 {
            return Ok(BannerCorrelationGraph::from_counts(
                HashMap::new(),
                HashMap::new(),
                0,
                seed_ports
            ));
        }

        let port_rows: Vec<(u16, u64)> = self.client
            .query("SELECT port, count(DISTINCT ip) AS cnt FROM ? GROUP BY port")
            .bind(Identifier(table))
            .fetch_all()
            .await?;

        let banner_counts: HashMap<u16, u64> = port_rows.into_iter().collect();
        let co_rows: Vec<(u16, u16, u64)> = self.client
            .query("SELECT a.port AS port_i, b.port AS port_j, count(DISTINCT a.ip) AS cnt \
                    FROM ? a \
                    INNER JOIN ? b ON a.ip = b.ip \
                    WHERE a.port != b.port \
                    GROUP BY port_i, port_j")
            .bind(Identifier(table))
            .bind(Identifier(table))
            .fetch_all()
            .await?;

        let co_banner_counts: HashMap<(u16, u16), u64> = co_rows.into_iter()
            .map(|(i, j, c)| ((i, j), c))
            .collect();

        Ok(BannerCorrelationGraph::from_counts(
            banner_counts,
            co_banner_counts,
            total,
            seed_ports
        ))
    }

    #[inline]
    pub async fn write_many<P: Parser>(
        &'_ self,
        rows: &[Scanling<P>],
    ) -> anyhow::Result<()> {
        let mut insert = self.client.insert::<Scanling<P>>(&self.shared.config.database.table).await?;

        for row in rows {
            insert.write(row).await?;
        }

        insert.end().await?;

        Ok(())
    }

    #[inline]
    pub async fn read_ranges(&self, count: usize) -> anyhow::Result<Vec<Ipv4Addr>> {
        let mut fetch = self.client.query("SELECT ip FROM ? GROUP BY ip;")
            .bind(Identifier(&self.shared.config.database.table))
            .fetch::<u32>()
            .context("fetching from database")?;

        let mut ranges = FxHashSet::default();
        while let Some(ip) = fetch.next().await? {
            ranges.insert(ip);

            if ranges.len() >= count {
                break;
            }
        }

        Ok(ranges
            .into_iter()
            .map(Ipv4Addr::from)
            .collect())
    }
}
