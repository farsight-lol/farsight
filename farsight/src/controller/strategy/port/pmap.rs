use std::collections::HashSet;
use std::hint::likely;
use std::mem;
use crate::config::PortRange;
use crate::controller::shared::SharedData;
use crossbeam_queue::{ArrayQueue, SegQueue};
use dashmap::DashMap;
use rand::RngExt;
use std::net::Ipv4Addr;
use std::ops::{Add, Deref, Sub};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use anyhow::Context;
use fxhash::{FxBuildHasher, FxHashMap};
use log::{debug, info, trace};
use crate::controller::strategy::pmap::graph::banner::PortGraph;
use crate::controller::strategy::pmap::heap::LazyHeap;
use crate::controller::strategy::port::{PortExpirer, PortAdapter};
use crate::database::Database;

pub struct PmapPortAdapter {
    pending: SegQueue<(u16, Ipv4Addr, u16)>,
    states: DashMap<Ipv4Addr, Box<State>, FxBuildHasher>,

    expiries: SegQueue<(Instant, Ipv4Addr)>,

    allocated_states: ArrayQueue<Box<State>>,

    graph: PortGraph,

    epsilon: f64,
    budget_per_address: usize,
    source_port: PortRange,
    timeout: Duration,

    in_flight_count: AtomicUsize,

    max_in_flight: usize,
}

#[derive(Default, Debug)]
struct State {
    tried_ports: HashSet<u16>,
    heap: LazyHeap<u16>,

    recommendation_index: usize,
    budget_remaining: usize,

    seen_responses: FxHashMap<u64, u8>,
}

impl State {
    #[inline]
    fn clear(&mut self, recommendation_index: usize, budget: usize) {
        self.tried_ports.clear();
        self.heap.clear();
        self.recommendation_index = recommendation_index;
        self.budget_remaining = budget;
        self.seen_responses.clear();
    }

    #[inline]
    fn prob(&self, graph: &PortGraph, port: u16) -> f64 {
        self.heap.query(port).unwrap_or_else(|| graph.base_prob(port))
    }

    #[inline]
    fn next_port(&mut self, graph: &PortGraph) -> Option<u16> {
        while let Some(port) = graph.recommend_at(self.recommendation_index) {
            if !self.tried_ports.contains(&port) {
                break;
            }

            self.recommendation_index += 1;
        }

        loop {
            match self.heap.top() {
                Some(port) if self.tried_ports.contains(&port) => self.heap.pop(),
                _ => break,
            }
        }

        let from_heap = self.heap.top();
        let from_list = graph.recommend_at(self.recommendation_index);

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
    fn record_banner(&mut self, graph: &PortGraph, port: u16, hash: u64) -> bool {
        self.tried_ports.insert(port);

        let count = self.seen_responses
            .entry(hash)
            .or_insert(0);

        *count += 1;
        if *count >= graph.threshold {
            return true;
        }

        let Some(co_occurring) = graph.co_occurring(port) else {
            return false;
        };

        let base_count = graph.open_count(port);
        if base_count == 0 {
            return false;
        }

        for (&other_port, &count) in co_occurring {
            let conditional_prob = count as f64 / base_count as f64;

            if conditional_prob > self.prob(graph, other_port) {
                self.heap.update(other_port, conditional_prob);
            }
        }

        false
    }

    #[inline]
    fn record_empty(&mut self, port: u16) {
        self.tried_ports.insert(port);
    }
}

pub struct PmapExpirer<'b> {
    states: &'b DashMap<Ipv4Addr, Box<State>, FxBuildHasher>,
    allocated_states: &'b ArrayQueue<Box<State>>,
    in_flight_count: &'b AtomicUsize,
    expiries: &'b SegQueue<(Instant, Ipv4Addr)>,
    pending: Option<(Instant, Ipv4Addr)>
}

impl PortExpirer for PmapExpirer<'_> {
    #[inline]
    fn expire(&mut self, now: Instant, batch_size: usize) {
        let mut removed = 0;
        for _ in 0..batch_size {
            let (expires_at, addr) = match self.pending.take() {
                Some(e) => e,
                None => match self.expiries.pop() {
                    Some(e) => e,
                    None => break,
                },
            };

            if expires_at > now {
                self.pending = Some((expires_at, addr));
                break;
            }

            if let Some((_, state)) = self.states.remove(&addr) {
                self.allocated_states.push(state).unwrap();
                removed += 1;
            }
        }

        self.in_flight_count.fetch_sub(removed, Ordering::Relaxed);
    }
}

impl PortAdapter for PmapPortAdapter {
    #[inline]
    async fn new(
        shared: SharedData,
        database: &mut Database,
        seed_ports: &[u16]
    ) -> anyhow::Result<Self> {
        let graph = database.build_graph(
            seed_ports
        ).await.context("building graph")?;

        let timeout = shared.config.strategy.timeout;
        let max_in_flight = (shared.config.strategy.max_rate
            * timeout.as_secs_f64()
            * 1.5)
            .round() as usize;

        let allocated_states = ArrayQueue::new(max_in_flight);
        for _ in 0..max_in_flight {
            allocated_states.push(Box::new(State::default())).unwrap();
        }

        Ok(Self {
            pending: SegQueue::new(),

            states: DashMap::with_capacity_and_hasher(max_in_flight, Default::default()),
            expiries: SegQueue::new(),

            allocated_states,

            graph,

            epsilon: shared.config.strategy.epsilon.port,
            budget_per_address: shared.config.strategy.budget_per_address as usize,
            source_port: shared.config.controller.source_port,
            timeout,

            in_flight_count: AtomicUsize::new(0),

            max_in_flight,
        })
    }

    #[inline]
    fn enqueue(&self, addr: Ipv4Addr, now: Instant, rng: &mut impl rand::Rng) {
        let mut state = self.allocated_states.pop().unwrap();

        let explore = rng.random_range::<f64, _>(0f64..=1f64) < self.epsilon;
        let (port, state) = if explore {
            state.clear(0, self.budget_per_address);

            (
                self.graph.explore_empty(rng),
                state
            )
        } else {
            state.clear(1, self.budget_per_address);

            (
                self.graph.recommend_at(0)
                    .unwrap_or_else(|| self.graph.explore_empty(rng)),
                state
            )
        };

        self.states.insert(addr, state);
        self.expiries.push((now.add(self.timeout), addr));

        let source_port = self.source_port.sample(rng);
        self.pending.push((source_port, addr, port));

        self.in_flight_count.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn on_result(&self, addr: Ipv4Addr, port: u16, hash: Option<u64>, rng: &mut impl rand::Rng) {
        let Some(mut state) = self.states.get_mut(&addr) else {
            return
        };

        if state.tried_ports.contains(&port) {
            return;
        }

        match hash {
            Some(hash) => {
                if state.record_banner(&self.graph, port, hash) {
                    info!("suspected honeypot, abandoning remaining budget for {addr}:{port}");

                    drop(state);

                    if let Some((_, state)) = self.states.remove(&addr) {
                        self.allocated_states.push(state).unwrap();
                        self.in_flight_count.fetch_sub(1, Ordering::Relaxed);
                    }

                    return;
                }
            },

            None => { state.record_empty(port); }
        };

        state.budget_remaining = state.budget_remaining.saturating_sub(1);
        if state.budget_remaining == 0 {
            drop(state);

            if let Some((_, state)) = self.states.remove(&addr) {
                self.allocated_states.push(state).unwrap();
                self.in_flight_count.fetch_sub(1, Ordering::Relaxed);
            }

            return;
        }

        let explore = rng.random_range::<f64, _>(0f64..=1f64) < self.epsilon;
        let next = if explore {
            self.graph.explore(&state.tried_ports, rng)
        } else {
            state.next_port(&self.graph)
                .or_else(|| self.graph.explore(&state.tried_ports, rng))
        };

        let Some(next_port) = next else {
            drop(state);

            if let Some((_, state)) = self.states.remove(&addr) {
                self.allocated_states.push(state).unwrap();
                self.in_flight_count.fetch_sub(1, Ordering::Relaxed);
            }

            return;
        };

        drop(state);

        let source_port = self.source_port.sample(rng);
        self.pending.push((source_port, addr, next_port));
    }

    #[inline]
    fn create_expirer(&self) -> impl PortExpirer {
        PmapExpirer {
            in_flight_count: &self.in_flight_count,
            allocated_states: &self.allocated_states,
            states: &self.states,
            expiries: &self.expiries,
            pending: None,
        }
    }

    #[inline(always)]
    fn length(&self) -> usize {
        self.in_flight_count.load(Ordering::Relaxed)
    }

    #[inline(always)]
    fn capacity(&self) -> usize {
        self.max_in_flight
    }

    #[inline]
    fn recv_into(&self, vec: &mut Vec<(u16, Ipv4Addr, u16)>, batch_size: usize) {
        for _ in 0..batch_size {
            match self.pending.pop() {
                Some(pending) => vec.push(pending),
                None => break
            }
        }
    }
}
