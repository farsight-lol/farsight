use anyhow::Error;
use serde::Serialize;
use std::{net::Ipv4Addr, ops::Deref};
use std::fmt::Debug;

pub mod minecraft;

#[derive(Debug)]
pub enum ParseError {
    Invalid,
    Incomplete,
}

pub trait Parser: Send + Sync + Debug {
    type Output: Sized + Send + Sync + Serialize + Debug;

    fn parse(
        &'_ self,
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
