use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;
use anyhow::Context;
use aya::Ebpf;
use enum_map::{enum_map, Enum, EnumMap};
use mongodb::action::InsertOne;
use mongodb::bson::{to_document, Bson, DateTime, Document};
use mongodb::options::{ClientOptions, InsertOneOptions, WriteConcern};
use mongodb::sync::{Client, Collection};
use serde::Serialize;
use tokio::runtime::Handle;
use toml::value::Datetime;
use crate::config::{CollectionConfig, MongoConfig, ParserKind};
use crate::controller::protocol::minecraft::SLPResponse;
use crate::controller::protocol::Parser;
use crate::controller::strategy::Strategy;

#[derive(Debug, Serialize)]
pub struct Scanling<P: Parser> {
    timestamp: DateTime,

    ip: Ipv4Addr,
    port: u16,

    response: P::Output
}

impl<P: Parser> Scanling<P> {
    #[inline]
    pub fn new(
        ip: Ipv4Addr,
        port: u16,
        response: P::Output
    ) -> Self {
        Self {
            timestamp: DateTime::now(),
            ip,
            port,
            response
        }
    }
}

pub struct Database {
    collections: EnumMap<ParserKind, Collection<Document>>
}

impl Database {
    #[inline]
    pub async fn new(config: MongoConfig) -> anyhow::Result<Self> {
        let client = Client::with_options(
            ClientOptions::parse(config.url)
                .await
                .context("parsing connection string")?
        ).context("establishing connection to database")?;

        let database = client.database(
            &config.database
        );

        Ok(Self {
            collections: enum_map! {
                ParserKind::Slp => database.collection(
                    config.collections
                        .iter()
                        .find(|x| x.parser == ParserKind::Slp)
                        .map(|x| &x.collection)
                        .context("missing parser type")?
                ),
            }
        })
    }

    #[inline]
    pub fn write<P: Parser>(&'_ self, row: &Scanling<P>) -> anyhow::Result<InsertOne<'_>> {
        Ok(self.collections[P::KIND].insert_one(
            to_document(row)
                .context("serializing row")?
        ))
    }
}
