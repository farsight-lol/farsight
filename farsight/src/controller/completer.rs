use std::sync::atomic::{AtomicUsize, Ordering};
use log::info;
use tokio::time::Instant;
use crate::xdp::ring::Consumer;

pub(super) struct Completer {
    cr: Consumer<u64>,
    started: Instant,
}

impl Completer {
    #[inline]
    pub(super) fn new(cr: Consumer<u64>) -> Self {
        Self { cr, started: Instant::now() }
    }

    #[inline]
    pub(super) fn tick(&mut self) -> bool {
        if self.cr.peek(1).is_some() {
            self.cr.release(1);
            
            true
        } else {
            false
        }
    }
}
