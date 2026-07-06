use std::collections::{BinaryHeap, HashMap};
use std::hash::Hash;
use std::sync::{Mutex, MutexGuard};
use dashmap::DashMap;
use fxhash::{FxBuildHasher};
use ordered_float::OrderedFloat;

#[derive(Debug, Default)]
pub struct ConcurrentLazyHeap<K: Copy + Eq + Hash + Ord> {
    values: DashMap<K, f64, FxBuildHasher>,
    current: Mutex<BinaryHeap<(OrderedFloat<f64>, K)>>,
    stale: Mutex<BinaryHeap<(OrderedFloat<f64>, K)>>,
}

impl<K: Copy + Eq + Hash + Ord> ConcurrentLazyHeap<K> {
    #[inline]
    pub fn top(&self) -> Option<K> {
        self._top().peek().map(|&(_, k)| k)
    }
    
    #[inline]
    pub fn _top(&'_ self) -> MutexGuard<'_, BinaryHeap<(OrderedFloat<f64>, K)>> {
        let mut current = self.current.lock().unwrap();
        let mut stale = self.stale.lock().unwrap();
        loop {
            match (current.peek(), stale.peek()) {
                (Some(a), Some(b)) if a.eq(b) => {
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
        if let Some((_, k)) = self._top().pop() {
            self.values.remove(&k);
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

#[derive(Debug, Default)]
pub struct LazyHeap<K: Copy + Eq + Hash + Ord> {
    values: HashMap<K, f64, FxBuildHasher>,
    current: BinaryHeap<(OrderedFloat<f64>, K)>,
    stale: BinaryHeap<(OrderedFloat<f64>, K)>,
}

impl<K: Copy + Eq + Hash + Ord> LazyHeap<K> {
    #[inline]
    pub fn top(&mut self) -> Option<K> {
        self._top();

        self.current.peek().map(|&(_, k)| k)
    }

    #[inline]
    pub fn _top(&mut self) {
        loop {
            match (self.current.peek(), self.stale.peek()) {
                (Some(&a), Some(&b)) if a == b => {
                    self.current.pop();
                    self.stale.pop();
                }
                _ => break,
            }
        }
    }

    #[inline]
    pub fn pop(&mut self) {
        self._top();
        if let Some((_, k)) = self.current.pop() {
            self.values.remove(&k);
        }
    }

    #[inline]
    pub fn query(&self, key: K) -> Option<f64> {
        self.values.get(&key).cloned()
    }

    #[inline]
    pub fn update(&mut self, key: K, value: f64) {
        if let Some(old) = self.values.get(&key) {
            self.stale.push((OrderedFloat(*old), key));
        }

        self.values.insert(key, value);
        self.current.push((OrderedFloat(value), key));
    }

    #[inline]
    pub fn clear(&mut self) {
        self.stale.clear();
        self.current.clear();
        self.values.clear();
    }
}

