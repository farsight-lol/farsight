use std::collections::BinaryHeap;
use fxhash::FxHashMap;
use ordered_float::OrderedFloat;

#[derive(Default)]
pub struct LazyHeap {
    values: FxHashMap<u16, f64>,
    current: BinaryHeap<(OrderedFloat<f64>, u16)>,
    stale: BinaryHeap<(OrderedFloat<f64>, u16)>,
}

impl LazyHeap {
    #[inline]
    pub fn top(&mut self) -> Option<u16> {
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
    pub fn query(&self, port: u16) -> Option<f64> {
        self.values.get(&port).copied()
    }

    #[inline]
    pub fn update(&mut self, port: u16, value: f64) {
        if let Some(&old) = self.values.get(&port) {
            self.stale.push((OrderedFloat(old), port));
        }

        self.values.insert(port, value);
        self.current.push((OrderedFloat(value), port));
    }
}
