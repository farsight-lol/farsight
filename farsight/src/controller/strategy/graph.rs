use std::collections::HashMap;
use rand::RngExt;

pub struct BannerCorrelationGraph {
    pub open_prob: HashMap<u16, f64>,
    pub edges: HashMap<u16, HashMap<u16, f64>>,

    sorted_ports: Vec<(u16, f64)>,
    total_addresses: u64
}

impl BannerCorrelationGraph {
    #[inline]
    pub fn from_counts(
        banner_counts: HashMap<u16, u64>,
        co_banner_counts: HashMap<(u16, u16), u64>,
        total_addresses: u64,
        seed_ports: &[u16],
    ) -> Self {
        let mut open_prob: HashMap<u16, f64> = if total_addresses == 0 {
            HashMap::new()
        } else {
            banner_counts.iter()
                .map(|(&port, &count)| (port, count as f64 / total_addresses as f64))
                .collect()
        };

        for &port in seed_ports {
            open_prob.entry(port).or_insert(0.0);
        }

        let mut edges: HashMap<u16, HashMap<u16, f64>> = HashMap::new();
        for ((i, j), &co_count) in &co_banner_counts {
            let Some(&count_i) = banner_counts.get(i) else {
                continue
            };

            if count_i == 0 {
                continue;
            }

            edges.entry(*i).or_default().insert(*j, co_count as f64 / count_i as f64);
        }

        let mut sorted_ports: Vec<(u16, f64)> = open_prob.into_iter().collect();
        sorted_ports.sort_unstable_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        Self { open_prob: sorted_ports.iter().cloned().collect(), edges, sorted_ports, total_addresses }
    }

    #[inline]
    pub(super) fn is_reliable(&self, min_samples: u64, min_ports: usize) -> bool {
        self.total_addresses >= min_samples && self.sorted_ports.len() >= min_ports
    }

    #[inline]
    pub(super) fn best_entry_port(&self) -> Option<u16> {
        self.sorted_ports.first().map(|(port, _)| *port)
    }

    pub(super) fn recommend_cascade(
        &self,
        confirmed: &[u16],
        tried: &[u16],
        budget: usize,
    ) -> Vec<u16> {
        if budget == 0 {
            return Vec::new();
        }

        let mut candidates: Vec<(u16, f64)> = self.sorted_ports
            .iter()
            .filter(|(port, _)| !tried.contains(port))
            .map(|&(port, base_prob)| {
                let posterior = confirmed.iter()
                    .filter_map(|&confirmed_port| {
                        self.edges
                            .get(&confirmed_port)?
                            .get(&port)
                            .copied()
                    })
                    .fold(base_prob, f64::max);
                (port, posterior)
            })
            .collect();

        candidates.sort_unstable_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        let mut result = Vec::with_capacity(budget);
        let mut max_pending_edge: f64 = 0.0;

        for (port, prob) in candidates.iter().take(budget) {
            if prob < &max_pending_edge && !result.is_empty() {
                break;
            }

            result.push(*port);

            if let Some(outgoing) = self.edges.get(port) {
                let max_edge = outgoing.values().cloned().fold(0.0f64, f64::max);
                max_pending_edge = max_pending_edge.max(max_edge);
            }
        }

        result
    }

    pub(super) fn explore(&self, tried: &[u16], rng: &mut impl rand::Rng) -> Option<u16> {
        let candidates: Vec<u16> = self.sorted_ports
            .iter()
            .map(|(port, _)| *port)
            .filter(|port| !tried.contains(port))
            .collect();

        if candidates.is_empty() {
            return None;
        }

        Some(candidates[rng.random_range(0..candidates.len())])
    }
}