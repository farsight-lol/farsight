use std::{alloc, ptr};
use std::sync::atomic::{AtomicIsize, Ordering};
use crossbeam_epoch::Atomic;
use crossbeam_utils::CachePadded;
use crate::controller::deque::buffer::Buffer;

pub mod worker;
pub mod stealer;
pub mod buffer;

pub(crate) struct Inner<T> {
    pub(crate) consumed: AtomicIsize,
    pub(crate) produced: AtomicIsize,

    pub(crate) buffer: CachePadded<Atomic<Buffer<T>>>,
}

impl<T> Drop for Inner<T> {
    #[inline]
    fn drop(&mut self) {
        let produced = *self.produced.get_mut();
        let consumed = *self.consumed.get_mut();

        unsafe {
            let buffer = self.buffer.load(Ordering::Relaxed, crossbeam_epoch::unprotected())
                .into_owned()
                .into_box();

            let mut current = consumed;
            while current != produced {
                let slot_ptr = buffer.at(current);
                ptr::drop_in_place(slot_ptr);
                current = current.wrapping_add(1);
            }

            alloc::dealloc(
                buffer.ptr.cast::<u8>(),
                buffer.layout,
            );
        }
    }
}
