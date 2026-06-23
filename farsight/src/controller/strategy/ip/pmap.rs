use std::net::Ipv4Addr;
use std::sync::{Mutex};
use anyhow::Context;
use dashmap::DashMap;
use fxhash::{FxBuildHasher};
use perfect_rand::PerfectRng;
use rand::RngExt;
use crate::controller::shared::SharedData;
use crate::controller::strategy::ip::IpAdapter;
use crate::controller::strategy::pmap::graph::prefix::{PrefixGraph, PrefixState};
use crate::controller::strategy::pmap::heap::LazyHeap;
use crate::database::Database;
use crate::net::range::CompiledRanges;

pub struct PmapIpAdapter {
    ranges: CompiledRanges,

    rng: PerfectRng,

    graph: PrefixGraph,
    heap: Mutex<LazyHeap<u32>>,
    actives: DashMap<u32, PrefixState, FxBuildHasher>,

    epsilon: f64,
}

impl PmapIpAdapter {
    fn try_pick(&self, rng: &mut impl rand::Rng) -> Option<Ipv4Addr> {
        let mut heap = self.heap.lock().unwrap();
        loop {
            let prefix_id = heap.top()?;

            let mut state = self.actives.entry(prefix_id).or_insert_with(PrefixState::new);
            if state.remaining == 0 {
                heap.pop();
                continue
            }

            match state.fetch_unscanned(rng) {
                Some(offset) => {
                    state.mark_scanned(offset);

                    if state.remaining == 0 {
                        heap.pop();
                    }

                    return Some(Ipv4Addr::from((prefix_id << 8) | offset as u32));
                }

                None => heap.pop()
            }
        }
    }

    #[inline]
    fn next(&self, index: &mut u64) -> Option<Ipv4Addr> {
        loop {
            let index_deref = *index;
            if index_deref >= self.ranges.count() as u64 {
                return None;
            }

            *index += 1;

            let shuffled = self.rng.shuffle(index_deref) as usize;
            let addr = self.ranges.index(shuffled);

            let prefix_id = u32::from(addr) >> 8;
            let offset = (u32::from(addr) & 0xFF) as u8;

            let mut state = self.actives.entry(prefix_id).or_insert_with(PrefixState::new);
            if state.mark_scanned(offset) {
                continue
            }

            if !state.remaining == 0 {
                let mut heap = self.heap.lock().unwrap();
                if heap.query(prefix_id).is_none() {
                    heap.update(prefix_id, self.graph.historical_score(prefix_id) as f64);
                }
            }

            return Some(addr);
        }
    }
}

impl IpAdapter for PmapIpAdapter {
    async fn new(
        shared: SharedData,
        database: &mut Database,
        ranges: CompiledRanges,
        seed: u64,
    ) -> anyhow::Result<Self> where Self: Sized {
        let graph = database.build_prefix_graph().await.context("building prefix graph")?;

        Ok(Self {
            epsilon: shared.config.strategy.epsilon.ip,
            rng: PerfectRng::new(
                ranges.count() as u64,
                seed,
                3
            ),

            heap: Default::default(),
            actives: Default::default(),

            ranges,
            graph,
        })
    }

    #[inline]
    fn next_address(&self, index: &mut u64, rng: &mut impl rand::Rng) -> Option<Ipv4Addr> {
        if rng.random_range::<f64, _>(0f64..=1f64) >= self.epsilon {
            if let Some(addr) = self.try_pick(rng) {
                return Some(addr);
            }
        }

        self.next(index)
            .or_else(|| self.try_pick(rng))
    }

    #[inline]
    fn on_result(&self, addr: Ipv4Addr) {
        let prefix_id = u32::from(addr) >> 8;

        let has_room = self.actives
            .get(&prefix_id)
            .map(|s| s.remaining > 0)
            .unwrap_or(true);

        if has_room {
            let mut heap = self.heap.lock().unwrap();
            let current = heap.query(prefix_id)
                .unwrap_or_else(|| self.graph.historical_score(prefix_id) as f64);

            heap.update(prefix_id, current + 1.0);
        }
    }
}