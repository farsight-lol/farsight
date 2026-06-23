use std::collections::BinaryHeap;
use std::hash::Hash;
use fxhash::FxHashMap;
use ordered_float::OrderedFloat;

#[derive(Default)]
pub struct LazyHeap<K: Copy + Eq + Hash + Ord> {
    values: FxHashMap<K, f64>,
    current: BinaryHeap<(OrderedFloat<f64>, K)>,
    stale: BinaryHeap<(OrderedFloat<f64>, K)>,
}

impl<K: Copy + Eq + Hash + Ord> LazyHeap<K> {
    #[inline]
    pub fn top(&mut self) -> Option<K> {
        loop {
            match (self.current.peek(), self.stale.peek()) {
                (Some(&a), Some(&b)) if a == b => {
                    self.current.pop();
                    self.stale.pop();
                }
                _ => break,
            }
        }

        self.current.peek().map(|&(_, port)| port)
    }

    #[inline]
    pub fn pop(&mut self) {
        if self.top().is_some() {
            self.current.pop();
        }
    }

    #[inline]
    pub fn query(&self, key: K) -> Option<f64> {
        self.values.get(&key).copied()
    }

    #[inline]
    pub fn update(&mut self, key: K, value: f64) {
        if let Some(&old) = self.values.get(&key) {
            self.stale.push((OrderedFloat(old), key));
        }

        self.values.insert(key, value);
        self.current.push((OrderedFloat(value), key));
    }
}
