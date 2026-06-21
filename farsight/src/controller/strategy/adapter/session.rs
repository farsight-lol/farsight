use crate::config::PortRange;
use crate::controller::shared::SharedData;
use crate::controller::strategy::graph::BannerCorrelationGraph;
use crossbeam_queue::SegQueue;
use dashmap::DashMap;
use rand::RngExt;
use rand_xorshift::XorShiftRng;
use std::net::Ipv4Addr;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use anyhow::Context;
use crate::controller::strategy::adapter::Adapter;
use crate::database::Database;

pub struct SessionAdapter {
    pending: SegQueue<(u16, Ipv4Addr, u16)>,
    states: DashMap<Ipv4Addr, State>,

    graph: BannerCorrelationGraph,

    epsilon: f64,
    budget_per_address: usize,
    source_port: PortRange,
    timeout: Duration,
}

struct State {
    confirmed_ports: Vec<u16>,
    tried_ports: Vec<u16>,
    budget_remaining: usize,
    started_at: Instant,
}

impl Adapter for SessionAdapter {
    #[inline]
    async fn new(
        shared: SharedData,
        database: &mut Database,
        seed_ports: &[u16]
    ) -> anyhow::Result<Self> {
        let graph = database.build_graph(
            seed_ports
        ).await.context("building graph")?;

        Ok(Self {
            pending: SegQueue::new(),
            states: DashMap::new(),

            graph,

            epsilon: shared.config.strategy.epsilon,
            budget_per_address: shared.config.strategy.budget_per_address as usize,
            source_port: shared.config.controller.source_port,
            timeout: shared.config.strategy.timeout,
        })
    }

    #[inline]
    fn enqueue_address(&self, addr: Ipv4Addr, rng: &mut XorShiftRng) {
        let state = State {
            confirmed_ports: Vec::new(),
            tried_ports: Vec::new(),
            budget_remaining: self.budget_per_address,
            started_at: Instant::now(),
        };

        self.states.insert(addr, state);

        let explore = rng.random_range::<f64, _>(0f64..=1f64) < self.epsilon;
        let initial_port = if explore || !self.graph.is_reliable(10, 1) {
            self.graph.explore(&[], rng)
        } else {
            self.graph.best_entry_port()
        };

        if let Some(port) = initial_port {
            let source_port = self.source_port.sample(rng);

            self.pending.push((source_port, addr, port));
        }
    }

    #[inline]
    fn on_banner(&self, addr: Ipv4Addr, port: u16, rng: &mut XorShiftRng) {
        let Some(mut state) = self.states.get_mut(&addr) else {
            return;
        };

        if state.tried_ports.contains(&port) {
            return;
        }

        state.tried_ports.push(port);
        state.confirmed_ports.push(port);
        state.budget_remaining = state.budget_remaining.saturating_sub(1);

        if state.budget_remaining == 0 {
            drop(state);

            self.states.remove(&addr);

            return;
        }

        let next_ports = if rng.random_range::<f64, _>(0f64..=1f64) < self.epsilon {
            self.graph.explore(&state.tried_ports, rng)
                .map(|p| vec![p])
                .unwrap_or_default()
        } else {
            self.graph.recommend_cascade(
                &state.confirmed_ports,
                &state.tried_ports,
                state.budget_remaining,
            )
        };

        let budget = state.budget_remaining;
        let to_push: Vec<u16> = next_ports.into_iter().take(budget).collect();
        state.budget_remaining -= to_push.len();

        drop(state);

        for port in to_push {
            let source_port = self.source_port.sample(rng);

            self.pending.push((source_port, addr, port));
        }
    }

    #[inline]
    fn on_empty(&self, addr: Ipv4Addr, port: u16, rng: &mut XorShiftRng) {
        let Some(mut state) = self.states.get_mut(&addr) else {
            return;
        };

        if state.tried_ports.contains(&port) {
            return;
        }

        state.tried_ports.push(port);
        state.budget_remaining = state.budget_remaining.saturating_sub(1);

        if state.budget_remaining == 0 {
            drop(state);

            self.states.remove(&addr);

            return;
        }

        let next_ports = if rng.random_range::<f64, _>(0f64..=1f64) < self.epsilon {
            self.graph.explore(&state.tried_ports, rng)
                .map(|p| vec![p])
                .unwrap_or_default()
        } else {
            self.graph.recommend_cascade(
                &state.confirmed_ports,
                &state.tried_ports,
                1,
            )
        };

        let budget = state.budget_remaining;
        let to_push: Vec<u16> = next_ports.into_iter().take(budget).collect();
        state.budget_remaining -= to_push.len();

        drop(state);

        for port in to_push {
            let source_port = self.source_port.sample(rng);

            self.pending.push((source_port, addr, port));
        }
    }

    #[inline]
    fn expire_timeouts(&self) {
        self.states.retain(|_, state| {
            state.started_at.elapsed() < self.timeout
        });
    }

    #[inline]
    fn pop(&self) -> Option<(u16, Ipv4Addr, u16)> {
        self.pending.pop()
    }
}
