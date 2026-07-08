use std::ptr::copy_nonoverlapping;
use std::sync::atomic;
use std::sync::atomic::Ordering;
use crossbeam_epoch::Guard;
use crate::controller::deque::Inner;

pub struct Stealer<'b, T> {
    pub(crate) inner: &'b Inner<T>,
}

impl<T> Clone for Stealer<'_, T> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner
        }
    }
}

unsafe impl<T: Send> Send for Stealer<'_, T> {}
unsafe impl<T: Send> Sync for Stealer<'_, T> {}

impl<T> Stealer<'_, T> {
    #[inline]
    pub fn steal(&self, guard: &Guard) -> Steal<T> {
        let f = self.inner.consumed.load(Ordering::Acquire);

        atomic::fence(Ordering::SeqCst);

        let b = self.inner.produced.load(Ordering::Acquire);

        let len = b.wrapping_sub(f).max(0) as usize;
        if len == 0 {
            return Steal::Empty;
        }

        let buffer = self.inner.buffer.load(Ordering::Acquire, guard);
        let task = unsafe { buffer.deref().read(f) };

        if self.inner.buffer.load(Ordering::Acquire, guard) != buffer
            || self
            .inner
            .consumed
            .compare_exchange(f, f.wrapping_add(1), Ordering::SeqCst, Ordering::Relaxed)
            .is_err()
        {
            return Steal::Retry;
        }

        Steal::Success(unsafe { task.assume_init() })
    }

    #[inline]
    pub fn steal_batch(&self, dest: &mut Vec<T>, guard: &Guard) -> Steal<()> {
        debug_assert!(dest.is_empty(), "steal_batch expects an empty destination buffer");

        let f = self.inner.consumed.load(Ordering::Acquire);

        atomic::fence(Ordering::SeqCst);

        let b = self.inner.produced.load(Ordering::Acquire);
        let len = b.wrapping_sub(f).max(0) as usize;

        let batch_size = usize::min(len.div_ceil(2), dest.capacity()) as isize;
        if batch_size == 0 {
            return Steal::Empty;
        }

        let buffer = self.inner.buffer.load(Ordering::Acquire, guard);
        unsafe {
            let dest = dest.as_mut_ptr();
            let buffer = buffer.deref();
            let copy_seg = |src_start: isize, dest_start: isize, count: isize| {
                copy_nonoverlapping(
                    buffer.ptr.offset(src_start),
                    dest.offset(dest_start),
                    count as usize
                );
            };

            let cap = buffer.cap as isize;
            let i = f & (cap - 1);
            if i + batch_size > cap {
                let l1 = cap - i;
                let l2 = batch_size - l1;

                copy_seg(i, 0, l1);
                copy_seg(0, l1, l2);
            } else {
                copy_seg(i, 0, batch_size);
            }
        }

        if self.inner.buffer.load(Ordering::Acquire, guard) != buffer
            || self
            .inner
            .consumed
            .compare_exchange(
                f,
                f.wrapping_add(batch_size),
                Ordering::SeqCst,
                Ordering::Relaxed,
            )
            .is_err()
        {
            dest.clear();

            return Steal::Retry;
        }

        unsafe { dest.set_len(batch_size as usize); }

        Steal::Success(())
    }
}

#[must_use]
pub enum Steal<T> {
    Empty,
    Retry,
    Success(T),
}
