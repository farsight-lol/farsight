pub mod ip;
pub mod port;
pub mod selector;

use std::fmt::Debug;
use std::marker::PhantomData;
use std::net::Ipv4Addr;
use std::ops::Add;
use anyhow::Context;
use enum_dispatch::enum_dispatch;
use serde::{Deserialize, Serialize, Serializer};
use crate::net::range::{AddressRanges, Ranges};

pub trait Strategy: Debug {
    type Output;

    fn generate_ranges(&self) -> anyhow::Result<Ranges<Self::Output>>;
}

pub trait StrategyTransformer: Strategy + Sized {
    #[inline]
    fn combine_with<O: Strategy>(self, other: O) -> CombinedStrategy<Self, O> {
        CombinedStrategy(self, other)
    }
}

impl<T: Strategy> StrategyTransformer for T {}

#[derive(Debug)]
pub struct CombinedStrategy<S1: Strategy, S2: Strategy>(S1, S2);

impl<S1: Strategy, S2: Strategy> Strategy for CombinedStrategy<S1, S2> where S1::Output: Clone, S2::Output: Clone {
    type Output = (S1::Output, S2::Output);

    #[inline]
    fn generate_ranges(&self) -> anyhow::Result<Ranges<Self::Output>> {
        let s1_ranges = self.0.generate_ranges()
            .context("generating s1 ranges")?.into_inner();
        let s2_ranges = self.1.generate_ranges()
            .context("generating s2 ranges")?.into_inner();

        let mut ranges = Vec::with_capacity(s1_ranges.len() * s2_ranges.len());
        for (s2_range, _) in s2_ranges {
            for (s1_range, _) in s1_ranges.clone() {
                ranges.push((s1_range.start, s2_range.start.clone())..(s1_range.end, s2_range.end.clone()));
            }
        }

        Ok(ranges.into())
    }
}
