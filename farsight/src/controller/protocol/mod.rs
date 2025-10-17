use anyhow::Error;
use std::{borrow::Cow, net::Ipv4Addr, ops::Deref};
use serde::Serialize;
use crate::config::ParserKind;

pub mod minecraft;

#[derive(Debug)]
pub enum ParseError {
    Invalid,
    Incomplete,
}

pub trait Parser: Send + Sync {
    const KIND: ParserKind;
    
    type Output: Sized + Send + Sync + Serialize;
    
    fn parse(
        &'_ self,
        ip: Ipv4Addr,
        port: u16,
        data: &'_ [u8],
    ) -> Result<Self::Output, ParseError>;
}

pub trait Payload: Send + Sync {
    fn build(&self, ip: Ipv4Addr, port: u16) -> Result<&[u8], Error>;
}

impl<T: Deref<Target = [u8]> + Send + Sync> Payload for T {
    #[inline]
    fn build(&self, _ip: Ipv4Addr, _port: u16) -> Result<&[u8], Error> {
        Ok(self)
    }
}
