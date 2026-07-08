use std::{alloc, ptr};
use std::alloc::Layout;
use std::mem::MaybeUninit;
use std::ops::Range;

pub(crate) struct Buffer<T> {
    pub(crate) layout: Layout,
    pub(crate) ptr: *mut T,
    pub(crate) cap: usize,
}

unsafe impl<T> Send for Buffer<T> {}

impl<T> Buffer<T> {
    #[inline]
    pub(crate) fn alloc(cap: usize) -> Buffer<T> {
        debug_assert_eq!(cap, cap.next_power_of_two());

        let layout = Layout::array::<T>(cap).unwrap();
        let ptr = unsafe {
            alloc::alloc(layout) as *mut _
        };

        Buffer { layout, ptr, cap }
    }

    #[inline]
    pub(crate) fn split_range(&self, range: Range<isize>) -> (Option<(usize, usize)>, Option<(usize, usize)>) {
        let len = range.end - range.start;
        if len <= 0 {
            return (None, None);
        }

        let cap = self.cap as isize;
        let i = range.start & (cap - 1);

        if i + len <= cap {
            (Some((i as usize, len as usize)), None)
        } else {
            let l1 = cap - i;
            let l2 = len - l1;
            (Some((i as usize, l1 as usize)), Some((0, l2 as usize)))
        }
    }

    #[inline(always)]
    pub(crate) const unsafe fn at(&self, index: isize) -> *mut T {
        unsafe {
            self.ptr.offset(index & (self.cap - 1) as isize)
        }
    }

    #[inline(always)]
    pub(crate) unsafe fn write(&self, index: isize, task: MaybeUninit<T>) {
        unsafe {
            ptr::write_volatile(self.at(index).cast::<MaybeUninit<T>>(), task)
        }
    }

    #[inline(always)]
    pub(crate) unsafe fn read(&self, index: isize) -> MaybeUninit<T> {
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