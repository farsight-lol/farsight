use std::collections::{HashMap, HashSet};
use rand::prelude::{IteratorRandom};

pub struct BannerCorrelationGraph {
    singles: HashMap<u16, u64>,
    doubles: HashMap<u16, HashMap<u16, u64>>,
    total: u64,

    recommendations: Vec<u16>,
}

impl BannerCorrelationGraph {
    pub fn from_counts(
        banner_counts: HashMap<u16, u64>,
        co_banner_counts: HashMap<(u16, u16), u64>,
        total_addresses: u64,
        seed_ports: &[u16],
    ) -> Self {
        let mut doubles: HashMap<u16, HashMap<u16, u64>> = HashMap::new();
        for ((i, j), count) in co_banner_counts {
            doubles.entry(i).or_default().insert(j, count);
        }

        let mut ordered: Vec<(u16, u64)> = banner_counts.iter().map(|(&p, &c)| (p, c)).collect();
        ordered.sort_unstable_by(|a, b| b.1.cmp(&a.1));

        let mut recommendations: Vec<u16> = ordered.into_iter().map(|(p, _)| p).collect();

        let already_present: HashSet<u16> = recommendations.iter().copied().collect();
        for &port in seed_ports {
            if !already_present.contains(&port) {
                recommendations.push(port);
            }
        }

        Self {
            singles: banner_counts,
            doubles,
            // floor at 1 to avoid division by zero; a cold-start graph (no
            // history yet) just means every port's base probability is 0.
            total: total_addresses.max(1),
            recommendations,
        }
    }

    #[inline]
    pub fn base_prob(&self, port: u16) -> f64 {
        self.singles.get(&port).copied().unwrap_or(0) as f64 / self.total as f64
    }

    #[inline]
    pub fn co_occurring(&self, port: u16) -> Option<&HashMap<u16, u64>> {
        self.doubles.get(&port)
    }

    #[inline]
    pub fn open_count(&self, port: u16) -> u64 {
        self.singles.get(&port).copied().unwrap_or(0)
    }

    #[inline]
    pub fn recommend_at(&self, index: usize) -> Option<u16> {
        self.recommendations.get(index).copied()
    }

    #[inline]
    pub fn explore(&self, tried: &HashSet<u16>, rng: &mut impl rand::Rng) -> Option<u16> {
        self.recommendations
            .iter()
            .copied()
            .filter(|port| !tried.contains(port))
            .choose(rng)
    }
}