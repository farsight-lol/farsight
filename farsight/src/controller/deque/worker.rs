use std::alloc;
use std::cell::Cell;
use std::marker::PhantomData;
use std::ptr::copy_nonoverlapping;
use std::sync::atomic::{AtomicIsize, Ordering};
use crossbeam_epoch::{Atomic, Guard, Owned};
use crossbeam_utils::CachePadded;
use crate::controller::deque::buffer::Buffer;
use crate::controller::deque::Inner;
use crate::controller::deque::stealer::Stealer;

// todo: make configurable maybe?
const MIN_CAP: usize = 64;
const FLUSH_THRESHOLD_BYTES: usize = 1 << 10;


pub struct Worker<T> {
    inner: CachePadded<Inner<T>>,

    buffer: Cell<Buffer<T>>,
    cached_cons: Cell<isize>,

    _marker: PhantomData<*mut ()>, // !Send + !Sync
}

unsafe impl<T: Send> Send for Worker<T> {}

impl<T> Worker<T> {
    #[inline]
    pub fn new() -> Worker<T> {
        let buffer = Buffer::alloc(MIN_CAP);

        Worker {
            inner: CachePadded::new(Inner {
                consumed: AtomicIsize::new(0),
                produced: AtomicIsize::new(0),
                buffer: CachePadded::new(Atomic::new(buffer)),
            }),

            buffer: Cell::new(buffer),
            cached_cons: Cell::new(0),

            _marker: PhantomData,
        }
    }

    #[inline(always)]
    pub fn stealer(&self) -> Stealer<'_, T> {
        Stealer {
            inner: &self.inner
        }
    }

    #[cold]
    unsafe fn resize(&self, new_cap: usize, guard: &Guard) {
        let prod = self.inner.produced.load(Ordering::Relaxed);
        let cons = self.inner.consumed.load(Ordering::Acquire);

        let old = self.buffer.get();
        let new = Buffer::<T>::alloc(new_cap);
        let copy_seg = |src_start: usize, dest_start: usize, count: usize| unsafe {
            copy_nonoverlapping(
                old.ptr.add(src_start),
                new.ptr.add(dest_start),
                count
            );
        };

        match (old.split_range(cons..prod), new.split_range(cons..prod)) {
            (
                (Some((s1, l1)), Some((s2, l2))),
                (Some((s3, l3)), Some((s4, l4)))
            ) => {
                debug_assert_eq!(l1 + l2, l3 + l4);

                if l1 <= l3 {
                    copy_seg(s1, s3, l1);

                    let rem = l3 - l1;
                    copy_seg(s2, s3 + l1, rem);
                    copy_seg(s2 + rem, s4, l2 - rem);
                } else {
                    copy_seg(s1, s3, l3);

                    let rem = l1 - l3;
                    copy_seg(s1 + l3, s4, rem);
                    copy_seg(s2, s4 + rem, l2);
                }
            },

            (
                (Some((s1, l1)), Some((s2, l2))),
                (Some((s3, l3)), None)
            ) => {
                debug_assert_eq!(l1 + l2, l3);

                copy_seg(s1, s3, l1);
                copy_seg(s2, s3 + l1, l2);
            },

            (
                (Some((s1, l1)), None),
                (Some((s3, l3)), Some((s4, l4)))
            ) => {
                debug_assert_eq!(l1, l3 + l4);

                copy_seg(s1, s3, l3);
                copy_seg(s1 + l3, s4, l4);
            },

            (
                (Some((s1, l1)), None),
                (Some((s3, l3)), None)
            ) => {
                debug_assert_eq!(l1, l3);

                copy_seg(s1, s3, l1);
            },

            _ => {}
        }

        self.buffer.replace(new);
        unsafe {
            let old =
                self.inner
                    .buffer
                    .swap(Owned::new(new).into_shared(guard), Ordering::Release, guard);

            guard.defer_unchecked(move || {
                let old = old.into_owned();

                alloc::dealloc(
                    old.ptr.cast::<u8>(),
                    old.layout,
                );
            });
        }

        if size_of::<T>() * new_cap >= FLUSH_THRESHOLD_BYTES {
            guard.flush();
        }
    }

    #[inline]
    pub fn push(&self, task: &[T], guard: &Guard) {
        let prod = unsafe { *self.inner.produced.as_ptr() };

        let mut buffer = self.buffer.get();
        let mut cons = self.cached_cons.get();

        if prod.wrapping_sub(cons) >= buffer.cap as isize {
            cons = self.inner.consumed.load(Ordering::Acquire);
            self.cached_cons.set(cons);

            if prod.wrapping_sub(cons) >= buffer.cap as isize {
                unsafe { self.resize(2 * buffer.cap, guard); }

                buffer = self.buffer.get();
            }
        }

        let task_len = task.len();
        let copy_seg = |src_start: usize, dest_start: usize, count: usize| unsafe {
            copy_nonoverlapping(
                task.as_ptr().add(src_start),
                buffer.ptr.add(dest_start),
                count
            );
        };

        let end = prod.wrapping_add(task_len as isize);
        match buffer.split_range(prod..end) {
            (Some((s1, l1)), Some((s2, l2))) => {
                debug_assert_eq!(task_len, l1 + l2);

                copy_seg(0, s1, l1);
                copy_seg(l1, s2, l2);
            }

            (Some((s1, l1)), None) => {
                debug_assert_eq!(task_len, l1);

                copy_seg(0, s1, l1);
            }

            _ => {}
        }

        // i don't think we're ever running this on anything else but x86 but oh well
        #[cfg(not(target_arch = "x86_64"))]
        atomic::fence(Ordering::Release);

        self.inner.produced.store(end, Ordering::Release);
    }
}