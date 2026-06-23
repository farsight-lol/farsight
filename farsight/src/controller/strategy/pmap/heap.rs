use std::collections::BinaryHeap;
use std::hash::Hash;
use std::sync::{Mutex, MutexGuard};
use dashmap::DashMap;
use fxhash::{FxBuildHasher, FxHashMap};
use ordered_float::OrderedFloat;

#[derive(Debug, Default)]
pub struct LazyHeap<K: Copy + Eq + Hash + Ord> {
    values: DashMap<K, f64, FxBuildHasher>,
    current: Mutex<BinaryHeap<(OrderedFloat<f64>, K)>>,
    stale: Mutex<BinaryHeap<(OrderedFloat<f64>, K)>>,
}

impl<K: Copy + Eq + Hash + Ord> LazyHeap<K> {
    #[inline]
    pub fn top(&self) -> Option<K> {
        self._top().peek().map(|&(_, port)| port)
    }
    
    #[inline]
    pub fn _top(&'_ self) -> MutexGuard<'_, BinaryHeap<(OrderedFloat<f64>, K)>> {
        let mut current = self.current.lock().unwrap();
        let mut stale = self.stale.lock().unwrap();
        loop {
            match (current.peek(), stale.peek()) {
                (Some(&a), Some(&b)) if a == b => {
                    current.pop();
                    stale.pop();
                }
                _ => break,
            }
        }
        
        drop(stale);

        current
    }

    #[inline]
    pub fn pop(&self) {
        let mut current = self._top();
        if current.peek().is_some() {
            current.pop();
        }
    }

    #[inline]
    pub fn query(&self, key: K) -> Option<f64> {
        self.values.get(&key).as_deref().cloned()
    }

    #[inline]
    pub fn update(&self, key: K, value: f64) {
        if let Some(old) = self.values.get(&key) {
            self.stale.lock().unwrap().push((OrderedFloat(*old), key));
        }

        self.values.insert(key, value);
        self.current.lock().unwrap().push((OrderedFloat(value), key));
    }

    #[inline]
    pub fn clear(&self) {
        self.stale.lock().unwrap().clear();
        self.current.lock().unwrap().clear();
        self.values.clear();
    }
}
