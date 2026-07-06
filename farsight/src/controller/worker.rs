// forked from crossbeam-deque

use std::cell::Cell;
use std::{alloc, cmp};
use std::alloc::Layout;
use std::marker::PhantomData;
use std::mem::{MaybeUninit};
use std::ops::Range;
use std::ptr;
use std::ptr::{copy_nonoverlapping};
use std::sync::atomic::{self, AtomicIsize, Ordering};

use crossbeam_epoch::{self as epoch, Atomic, Guard, Owned};
use crossbeam_utils::CachePadded;

// todo: make configurable maybe?
const MIN_CAP: usize = 64;
const FLUSH_THRESHOLD_BYTES: usize = 1 << 10;

struct Buffer<T> {
    layout: Layout,
    ptr: *mut T,
    cap: usize,
}

unsafe impl<T> Send for Buffer<T> {}

impl<T> Buffer<T> {
    #[inline]
    fn alloc(cap: usize) -> Buffer<T> {
        debug_assert_eq!(cap, cap.next_power_of_two());

        let layout = Layout::array::<T>(cap).unwrap();
        let ptr = unsafe {
            alloc::alloc(layout) as *mut _
        };

        Buffer { layout, ptr, cap }
    }

    #[inline]
    fn split_range(&self, range: Range<usize>) -> (Option<(usize, usize)>, Option<(usize, usize)>) {
        let len = range.end - range.start;
        if len == 0 {
            return (None, None);
        }

        let i = range.start & (self.cap - 1);

        if i + len <= self.cap {
            (Some((i, len)), None)
        } else {
            let l1 = self.cap - i;
            let l2 = len - l1;
            (Some((i, l1)), Some((0, l2)))
        }
    }

    #[inline(always)]
    const unsafe fn at(&self, index: isize) -> *mut T {
        unsafe {
            self.ptr.offset(index & (self.cap - 1) as isize)
        }
    }

    #[inline(always)]
    unsafe fn write(&self, index: isize, task: MaybeUninit<T>) {
        unsafe {
            ptr::write_volatile(self.at(index).cast::<MaybeUninit<T>>(), task)
        }
    }

    #[inline(always)]
    unsafe fn read(&self, index: isize) -> MaybeUninit<T> {
        unsafe {
            ptr::read_volatile(self.at(index).cast::<MaybeUninit<T>>())
        }
    }
}

impl<T> Clone for Buffer<T> {
    #[inline(always)]
    fn clone(&self) -> Buffer<T> {
        *self
    }
}

impl<T> Copy for Buffer<T> {}

struct Inner<T> {
    front: AtomicIsize,
    back: AtomicIsize,

    buffer: CachePadded<Atomic<Buffer<T>>>,
}

impl<T> Drop for Inner<T> {
    #[inline]
    fn drop(&mut self) {
        let b = *self.back.get_mut();
        let f = *self.front.get_mut();

        unsafe {
            let buffer = self.buffer.load(Ordering::Relaxed, epoch::unprotected())
                .into_owned()
                .into_box();

            let mut current = f;
            while current != b {
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

pub struct Worker<T> {
    inner: CachePadded<Inner<T>>,

    buffer: Cell<Buffer<T>>,
    cached_front: Cell<isize>,

    _marker: PhantomData<*mut ()>, // !Send + !Sync
}

unsafe impl<T: Send> Send for Worker<T> {}

impl<T> Worker<T> {
    #[inline]
    pub fn new() -> Worker<T> {
        let buffer = Buffer::alloc(MIN_CAP);

        Worker {
            inner: CachePadded::new(Inner {
                front: AtomicIsize::new(0),
                back: AtomicIsize::new(0),
                buffer: CachePadded::new(Atomic::new(buffer)),
            }),

            buffer: Cell::new(buffer),
            cached_front: Cell::new(0),

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
        let b = self.inner.back.load(Ordering::Relaxed);
        let f = self.inner.front.load(Ordering::Acquire);

        let old = self.buffer.get();
        let new = Buffer::<T>::alloc(new_cap);
        let copy_seg = |src_start: usize, dest_start: usize, count: usize| unsafe {
            copy_nonoverlapping(
                old.ptr.add(src_start),
                new.ptr.add(dest_start),
                count
            );
        };

        match (old.split_range(f as usize..b as usize), new.split_range(f as usize..b as usize)) {
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
    pub fn push(&self, task: T, guard: &Guard) {
        let b = self.inner.back.load(Ordering::Relaxed);

        let mut buffer = self.buffer.get();
        let mut cf = self.cached_front.get();

        if b.wrapping_sub(cf) >= buffer.cap as isize {
            cf = self.inner.front.load(Ordering::Acquire);
            self.cached_front.set(cf);

            if b.wrapping_sub(cf) >= buffer.cap as isize {
                unsafe { self.resize(2 * buffer.cap, guard); }
                buffer = self.buffer.get();
            }
        }

        unsafe {
            buffer.write(b, MaybeUninit::new(task));
        }

        // i don't think we're ever running this on anything else but x86 but oh well
        #[cfg(not(target_arch = "x86_64"))]
        atomic::fence(Ordering::Release);

        self.inner.back.store(b.wrapping_add(1), Ordering::Release);
    }
}

#[derive(Clone)]
pub struct Stealer<'b, T> {
    inner: &'b Inner<T>,
}

unsafe impl<T: Send> Send for Stealer<'_, T> {}
unsafe impl<T: Send> Sync for Stealer<'_, T> {}

impl<T> Stealer<'_, T> {
    #[inline]
    pub fn steal(&self, guard: &Guard) -> Steal<T> {
        let f = self.inner.front.load(Ordering::Acquire);

        atomic::fence(Ordering::SeqCst);

        let b = self.inner.back.load(Ordering::Acquire);

        let len = b.wrapping_sub(f).max(0) as usize;
        if len == 0 {
            return Steal::Empty;
        }

        let buffer = self.inner.buffer.load(Ordering::Acquire, guard);
        let task = unsafe { buffer.deref().read(f) };

        if self.inner.buffer.load(Ordering::Acquire, guard) != buffer
            || self
            .inner
            .front
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

        let f = self.inner.front.load(Ordering::Acquire);

        atomic::fence(Ordering::SeqCst);

        let b = self.inner.back.load(Ordering::Acquire);
        let len = b.wrapping_sub(f).max(0) as usize;

        let batch_size = cmp::min(len.div_ceil(2), dest.capacity()) as isize;
        if batch_size == 0 {
            unsafe { dest.set_len(0); }

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
            .front
            .compare_exchange(
                f,
                f.wrapping_add(batch_size),
                Ordering::SeqCst,
                Ordering::Relaxed,
            )
            .is_err()
        {
            unsafe { dest.set_len(0); }

            return Steal::Retry;
        }

        unsafe { dest.set_len(batch_size as usize); }

        Steal::Success(())
    }
}

#[must_use]
#[derive(PartialEq, Eq, Copy, Clone)]
pub enum Steal<T> {
    Empty,
    Success(T),
    Retry,
}
