use std::collections::HashSet;
use crate::config::PortRange;
use crate::controller::shared::SharedData;
use crate::controller::strategy::pmap::graph::BannerCorrelationGraph;
use crossbeam_queue::SegQueue;
use dashmap::DashMap;
use rand::RngExt;
use rand_xorshift::XorShiftRng;
use std::net::Ipv4Addr;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use anyhow::Context;
use log::debug;
use crate::controller::strategy::adapter::Adapter;
use crate::controller::strategy::pmap::heap::LazyHeap;
use crate::database::Database;

pub struct PmapAdapter {
    pending: SegQueue<(u16, Ipv4Addr, u16)>,
    states: DashMap<Ipv4Addr, State>,

    graph: BannerCorrelationGraph,

    epsilon: f64,
    budget_per_address: usize,
    source_port: PortRange,
    timeout: Duration,

    in_flight_count: AtomicUsize,

    max_in_flight: usize,
}

struct State {
    tried_ports: HashSet<u16>,
    heap: LazyHeap,
    recommend_index: usize,
    budget_remaining: usize,
    started_at: Instant,
}

impl State {
    #[inline]
    fn new(budget: usize) -> Self {
        Self {
            tried_ports: HashSet::new(),
            heap: LazyHeap::default(),
            recommend_index: 0,
            budget_remaining: budget,
            started_at: Instant::now(),
        }
    }

    #[inline]
    fn prob(&self, graph: &BannerCorrelationGraph, port: u16) -> f64 {
        self.heap.query(port).unwrap_or_else(|| graph.base_prob(port))
    }

    #[inline]
    fn next_port(&mut self, graph: &BannerCorrelationGraph) -> Option<u16> {
        while let Some(port) = graph.recommend_at(self.recommend_index) {
            if !self.tried_ports.contains(&port) {
                break;
            }
            self.recommend_index += 1;
        }

        loop {
            match self.heap.top() {
                Some(port) if self.tried_ports.contains(&port) => self.heap.pop(),
                _ => break,
            }
        }

        let from_heap = self.heap.top();
        let from_list = graph.recommend_at(self.recommend_index);

        match (from_heap, from_list) {
            (Some(a), Some(b)) => {
                if self.prob(graph, a) > self.prob(graph, b) { Some(a) } else { Some(b) }
            }
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }

    #[inline]
    fn record_result<const OPEN: bool>(&mut self, graph: &BannerCorrelationGraph, port: u16) {
        self.tried_ports.insert(port);

        if !OPEN {
            return;
        }

        let Some(co_occurring) = graph.co_occurring(port) else {
            return;
        };

        let base_count = graph.open_count(port);
        if base_count == 0 {
            return;
        }

        for (&other_port, &count) in co_occurring {
            let conditional_prob = count as f64 / base_count as f64;

            if conditional_prob > self.prob(graph, other_port) {
                self.heap.update(other_port, conditional_prob);
            }
        }
    }
}

impl Adapter for PmapAdapter {
    #[inline]
    async fn new(
        shared: SharedData,
        database: &mut Database,
        seed_ports: &[u16]
    ) -> anyhow::Result<Self> {
        let graph = database.build_graph(seed_ports).await.context("building graph")?;

        let timeout = shared.config.strategy.timeout;

        let max_in_flight = (shared.config.controller.max_rate as f64
            * timeout.as_secs_f64()
            * 1.5)
            .ceil() as usize;
        let max_in_flight = max_in_flight.max(1_000);

        let estimated_mb = (max_in_flight * 150) / (1024 * 1024);
        debug!(
            "calculated max_in_flight = {max_in_flight} (max_rate = {}; timeout = {timeout:?}); \
             estimated worst-case memory = {estimated_mb}MB",
            shared.config.controller.max_rate
        );

        Ok(Self {
            pending: SegQueue::new(),
            states: DashMap::new(),

            graph,

            epsilon: shared.config.strategy.epsilon,
            budget_per_address: shared.config.strategy.budget_per_address as usize,
            source_port: shared.config.controller.source_port,
            timeout,

            in_flight_count: AtomicUsize::new(0),

            max_in_flight,
        })
    }

    #[inline]
    fn enqueue_address(&self, addr: Ipv4Addr, rng: &mut XorShiftRng) {
        let mut state = State::new(self.budget_per_address);

        let port = if rng.random_range::<f64, _>(0f64..=1f64) < self.epsilon {
            self.graph.explore(&state.tried_ports, rng)
        } else {
            state.next_port(&self.graph)
        };

        let Some(port) = port else {
            return;
        };

        let source_port = self.source_port.sample(rng);
        self.pending.push((source_port, addr, port));

        self.states.insert(addr, state);
    }

    #[inline]
    fn on_result<const OPEN: bool>(&self, addr: Ipv4Addr, port: u16, rng: &mut XorShiftRng) {
        let Some(mut state) = self.states.get_mut(&addr) else {
            return;
        };

        if state.tried_ports.contains(&port) {
            return;
        }

        state.record_result::<OPEN>(&self.graph, port);
        state.budget_remaining = state.budget_remaining.saturating_sub(1);

        if state.budget_remaining == 0 {
            drop(state);
            self.states.remove(&addr);
            return;
        }

        let next = if rng.random_range::<f64, _>(0f64..=1f64) < self.epsilon {
            self.graph.explore(&state.tried_ports, rng)
        } else {
            state.next_port(&self.graph)
        };

        let Some(next_port) = next else {
            // exhausted every candidate port for this address
            drop(state);
            self.states.remove(&addr);
            return;
        };

        drop(state);

        let source_port = self.source_port.sample(rng);
        self.pending.push((source_port, addr, next_port));
    }

    #[inline]
    fn expire_timeouts(&self) {
        let mut total = 0;
        self.states.retain(|_, state| {
            if state.started_at.elapsed() < self.timeout {
                true
            } else {
                total += 1;

                false
            }
        });

        self.in_flight_count.fetch_sub(total, Ordering::Relaxed);
    }

    #[inline]
    fn is_at_capacity(&self) -> bool {
        // DashMap.len is very slow
        self.in_flight_count.load(Ordering::Relaxed) >= self.max_in_flight
    }

    #[inline]
    fn pop(&self) -> Option<(u16, Ipv4Addr, u16)> {
        self.pending.pop()
    }
}
