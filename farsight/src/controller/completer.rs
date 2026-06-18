use std::num::NonZeroUsize;
use crate::xdp::ring::Consumer;

pub(super) struct Completer {
    cr: Consumer<u64>,
}

impl Completer {
    #[inline]
    pub(super) fn new(cr: Consumer<u64>) -> Self {
        Self { cr }
    }

    #[inline]
    pub(super) fn tick(&mut self) -> Option<NonZeroUsize> {
        match self.cr.peek(self.cr.size()) {
            Some((_, count)) => {
                self.cr.release(count);

                NonZeroUsize::new(count as usize)
            }
            None => None,
        }
    }
}
