use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::hint::likely;
use std::mem;
use crate::config::PortRange;
use crate::controller::shared::SharedData;
use crossbeam_queue::{ArrayQueue};
use dashmap::DashMap;
use rand::{RngExt};
use std::net::Ipv4Addr;
use std::ops::{Add, Deref, Sub};
use std::sync::Arc;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use std::thread::Thread;
use std::time::{Duration, Instant};
use anyhow::{anyhow, Context};
use crossbeam_epoch::Guard;
use fxhash::{FxBuildHasher, FxHashMap};
use log::{debug, info, trace};
use crate::controller::deque::stealer::{Steal, Stealer};
use crate::controller::deque::worker::Worker;
use crate::controller::strategy::pmap::graph::banner::PortGraph;
use crate::controller::strategy::pmap::heap::LazyHeap;
use crate::controller::strategy::port::{PortExpirer, PortAdapter, PortGuard, PortGenerator, PortGenerationGuard, Expiry, PortBatcher};
use crate::database::Database;
use crate::net::tcp::PacketTemplate;

pub struct PmapPortAdapter {
    states: DashMap<Ipv4Addr, Box<State>, FxBuildHasher>,
    allocated_states: ArrayQueue<Box<State>>,

    graph: PortGraph,

    epsilon: f64,
    budget_per_address: usize,
    source_port: PortRange
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
    fn record_hit(&mut self, graph: &PortGraph, port: u16, hash: u64) -> bool {
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

pub struct PmapPortGenerationGuard<'env> {
    state: Box<State>,

    states: &'env DashMap<Ipv4Addr, Box<State>, FxBuildHasher>,
    allocated_states: &'env ArrayQueue<Box<State>>,
    graph: &'env PortGraph,

    source_port: PortRange,
    epsilon: f64,
    budget_per_address: usize,
}

impl PortGenerationGuard for PmapPortGenerationGuard<'_> {
    #[inline]
    fn generate(mut self, addr: Ipv4Addr, rng: &mut impl rand::Rng) -> PacketTemplate {
        let exploit = rng.random_range::<f64, _>(0f64..=1f64) >= self.epsilon;
        self.state.clear(usize::from(exploit), self.budget_per_address);

        let port = if exploit {
            self.graph.recommend_at(0)
                .unwrap_or_else(|| self.graph.explore_empty(rng))
        } else {
            self.graph.explore_empty(rng)
        };

        if let Some(state) = self.states.insert(addr, self.state) {
            self.allocated_states.push(state).unwrap();
        }

        let source_port = self.source_port.sample(rng);
        PacketTemplate::new(source_port, addr, port)
    }
}

pub struct PmapPortGenerator<'env> {
    states: &'env DashMap<Ipv4Addr, Box<State>, FxBuildHasher>,
    allocated_states: &'env ArrayQueue<Box<State>>,
    graph: &'env PortGraph,

    source_port: PortRange,
    epsilon: f64,
    budget_per_address: usize,
}

impl PortGenerator for PmapPortGenerator<'_> {
    #[inline(always)]
    fn guard(&self) -> Option<impl PortGenerationGuard> {
        Some(PmapPortGenerationGuard {
            state: self.allocated_states.pop()?,

            states: self.states,
            allocated_states: self.allocated_states,
            graph: self.graph,

            source_port: self.source_port,
            epsilon: self.epsilon,
            budget_per_address: self.budget_per_address,
        })
    }
}

pub struct PmapPortBatcher<'env> {
    results: &'env Worker<PacketTemplate>,
    expiries: &'env Worker<Expiry>
}

impl<'env> PortBatcher<'env> for PmapPortBatcher<'env> {
    #[inline]
    fn batch(
        &mut self,
        result_batch: &[PacketTemplate],
        expiries_batch: &[Expiry],
        guard: &Guard
    ) {
        self.results.push(result_batch, guard);
        self.expiries.push(expiries_batch, guard);
    }

    #[inline(always)]
    fn stealer(&self) -> Stealer<'env, PacketTemplate> {
        self.results.stealer()
    }
}

pub struct PmapPortGuard<'env> {
    states: &'env DashMap<Ipv4Addr, Box<State>, FxBuildHasher>,
    allocated_states: &'env ArrayQueue<Box<State>>,
    graph: &'env PortGraph,

    results: Worker<PacketTemplate>,
    expiries: Worker<Expiry>,

    source_port: PortRange,
    epsilon: f64,
    budget_per_address: usize,
}

impl PortGuard for PmapPortGuard<'_> {
    #[inline(always)]
    fn generator(&self) -> impl PortGenerator {
        PmapPortGenerator {
            states: self.states,
            allocated_states: self.allocated_states,
            graph: self.graph,

            source_port: self.source_port,
            epsilon: self.epsilon,
            budget_per_address: self.budget_per_address,
        }
    }

    #[inline(always)]
    fn batcher(&'_ self) -> impl PortBatcher<'_> {
        PmapPortBatcher {
            results: &self.results,
            expiries: &self.expiries,
        }
    }

    #[inline(always)]
    fn expirer(&self, batch_size: usize) -> impl PortExpirer {
        PmapPortExpirer {
            states: self.states,
            allocated_states: self.allocated_states,
            expiries: self.expiries.stealer(),
            pending: None,
            batch_size,
        }
    }
}

pub struct PmapPortExpirer<'env> {
    states: &'env DashMap<Ipv4Addr, Box<State>, FxBuildHasher>,
    allocated_states: &'env ArrayQueue<Box<State>>,

    expiries: Stealer<'env, (Instant, Ipv4Addr)>,
    pending: Option<(Instant, Ipv4Addr)>,
    batch_size: usize
}

impl<'env> PortExpirer for PmapPortExpirer<'env> {
    #[inline]
    fn expire(&mut self, now: Instant, guard: &Guard) {
        'f: for _ in 0..self.batch_size {
            let (expires_at, key) = match self.pending.take() {
                Some(e) => e,
                None => loop {
                    match self.expiries.steal(guard) {
                        Steal::Empty => break 'f,
                        Steal::Success(expiry) => break expiry,
                        Steal::Retry => continue
                    }
                },
            };

            if expires_at > now {
                self.pending = Some((expires_at, key));
                break;
            }

            if let Some((_, state)) = self.states.remove(&key) {
                self.allocated_states.push(state).unwrap();
            }
        }
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

        let max_in_flight = shared.config.strategy.max_in_flight;
        debug!("memory to be allocated for strategy = {}MB", max_in_flight * size_of::<State>() / (1024 * 1024));

        let allocated_states = ArrayQueue::new(max_in_flight);
        for _ in 0..max_in_flight {
            allocated_states.push(Box::new(State::default())).unwrap();
        }

        Ok(Self {
            states: DashMap::with_capacity_and_hasher(max_in_flight, Default::default()),
            allocated_states,

            graph,

            epsilon: shared.config.strategy.epsilon.port,
            budget_per_address: shared.config.strategy.budget_per_address as usize,
            source_port: shared.config.controller.source_port,
        })
    }

    #[inline]
    fn on_result(&self, addr: Ipv4Addr, port: u16, hash: Option<u64>, rng: &mut impl rand::Rng) -> Option<PacketTemplate> {
        let mut state = self.states.get_mut(&addr)?;
        if state.tried_ports.contains(&port) {
            return None;
        }

        match hash {
            Some(hash) => {
                let honeypot = state.record_hit(&self.graph, port, hash);
                if honeypot {
                    info!("suspected honeypot, abandoning remaining budget for {addr}:{port}");

                    drop(state);
                    self.remove_state(&addr);

                    return None;
                }
            },

            None => { state.record_empty(port); }
        };

        state.budget_remaining = state.budget_remaining.saturating_sub(1);
        if state.budget_remaining == 0 {
            drop(state);
            self.remove_state(&addr);

            return None;
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
            self.remove_state(&addr);

            return None;
        };

        drop(state);

        let source_port = self.source_port.sample(rng);
        Some(PacketTemplate::new(source_port, addr, next_port))
    }

    #[inline(always)]
    fn guard(&self) -> impl PortGuard {
        PmapPortGuard {
            states: &self.states,
            allocated_states: &self.allocated_states,
            results: Worker::new(),
            expiries: Worker::new(),
            graph: &self.graph,

            source_port: self.source_port,
            epsilon: self.epsilon,
            budget_per_address: self.budget_per_address,
        }
    }
}

impl PmapPortAdapter {
    #[inline]
    pub(crate) fn remove_state(&self, addr: &Ipv4Addr) {
        if let Some((_, state)) = self.states.remove(addr) {
            self.allocated_states.push(state).unwrap();
        }
    }
}
