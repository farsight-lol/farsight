use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crate::xdp::ring::Consumer;

pub struct Completer<'b> {
    cr: Consumer<u64>,
    completed: &'b AtomicUsize,
}

impl<'b> Completer<'b> {
    #[inline]
    pub fn new(
        cr: Consumer<u64>,
        completed: &'b AtomicUsize
    ) -> Self {
        Self {
            cr,
            completed
        }
    }

    #[inline]
    pub(super) fn tick(&mut self) {
        if let Some((_, count)) = self.cr.peek(self.cr.size()) {
            self.cr.release(count);

            self.completed.fetch_add(count as usize, Ordering::Relaxed);
        }
    }

    #[inline]
    pub(super) fn into_inner(self) -> Consumer<u64> {
        self.cr
    }
}
