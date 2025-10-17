use crate::{cbail, xdp::socket::Socket};
use anyhow::Context;
use bitflags::bitflags;
use libc::{
    mmap, munmap, MAP_ANONYMOUS, MAP_FAILED, MAP_NORESERVE,
    MAP_POPULATE, MAP_PRIVATE, MAP_SHARED, PROT_READ, PROT_WRITE,
    SOL_XDP, XDP_MMAP_OFFSETS, XDP_PGOFF_RX_RING, XDP_PGOFF_TX_RING,
    XDP_RING_NEED_WAKEUP, XDP_RX_RING, XDP_TX_RING,
    XDP_UMEM_COMPLETION_RING, XDP_UMEM_FILL_RING, XDP_UMEM_PGOFF_COMPLETION_RING,
    XDP_UMEM_PGOFF_FILL_RING,
};
use std::{
    ops::{Deref, DerefMut, Index, IndexMut},
    os::fd::AsRawFd,
    ptr::{null_mut, NonNull},
    slice::SliceIndex,
    sync::atomic::{AtomicU32, Ordering},
};
use strength_reduce::StrengthReducedU32;

#[inline(always)]
pub fn load_u32(ptr: NonNull<u32>, ordering: Ordering) -> u32 {
    unsafe { AtomicU32::from_ptr(ptr.as_ptr()) }.load(ordering)
}

#[inline(always)]
pub fn fetch_add_u32(ptr: NonNull<u32>, value: u32, ordering: Ordering) -> u32 {
    unsafe { AtomicU32::from_ptr(ptr.as_ptr()) }.fetch_add(value, ordering)
}

#[repr(C)]
#[derive(Debug)]
pub struct Descriptor {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}

bitflags! {
    pub struct MmapFlags: i32 {
        const Private = MAP_PRIVATE;
        const Anonymous = MAP_ANONYMOUS;
        const NoReserve = MAP_NORESERVE;
        const Shared = MAP_SHARED;
        const Populate = MAP_POPULATE;
    }
}

#[repr(C)]
pub struct RingOffset {
    pub producer: u64,
    pub consumer: u64,
    pub desc: u64,
    pub flags: u64,
}

#[repr(C)]
pub struct MmapOffsets {
    pub rx: RingOffset,
    pub tx: RingOffset,
    pub fr: RingOffset,
    pub cr: RingOffset,
}

impl MmapOffsets {
    #[inline]
    pub const fn get_offset(&self, kind: &RingKind) -> &RingOffset {
        match kind {
            RingKind::Fill => &self.fr,
            RingKind::Complete => &self.cr,
            RingKind::Tx => &self.tx,
            RingKind::Rx => &self.rx,
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum RingKind {
    Fill,
    Complete,
    Tx,
    Rx,
}

impl RingKind {
    #[inline]
    pub const fn get_page_offset(&self) -> i64 {
        match self {
            RingKind::Fill => XDP_UMEM_PGOFF_FILL_RING as _,
            RingKind::Complete => XDP_UMEM_PGOFF_COMPLETION_RING as _,
            RingKind::Tx => XDP_PGOFF_TX_RING,
            RingKind::Rx => XDP_PGOFF_RX_RING,
        }
    }

    #[inline]
    pub const fn get_opt_name(&self) -> i32 {
        match self {
            RingKind::Fill => XDP_UMEM_FILL_RING,
            RingKind::Complete => XDP_UMEM_COMPLETION_RING,
            RingKind::Tx => XDP_TX_RING,
            RingKind::Rx => XDP_RX_RING,
        }
    }
}

pub struct RingAllocator<'b> {
    socket: &'b Socket,
    offsets: MmapOffsets,
}

impl<'b> RingAllocator<'b> {
    pub(super) fn new(socket: &'b Socket) -> Result<Self, anyhow::Error> {
        let offsets = socket
            .get_opt(SOL_XDP, XDP_MMAP_OFFSETS)
            .context("getting mmap offsets")?;

        Ok(Self { socket, offsets })
    }

    fn ring<T>(
        &self,
        kind: RingKind,
        size: u32,
    ) -> Result<Ring<T>, anyhow::Error> {
        self.socket
            .set_opt(SOL_XDP, kind.get_opt_name(), &size)
            .context("setting ring size opt")?;

        Ring::new(self, kind, size).context("creating ring")
    }

    #[inline]
    pub fn tx(&self, size: u32) -> Result<Producer<Descriptor>, anyhow::Error> {
        self.ring(RingKind::Tx, size).map(Into::into)
    }

    #[inline]
    pub fn fr(&self, size: u32) -> Result<Producer<u64>, anyhow::Error> {
        self.ring(RingKind::Fill, size).map(Into::into)
    }

    #[inline]
    pub fn rx(&self, size: u32) -> Result<Consumer<Descriptor>, anyhow::Error> {
        self.ring(RingKind::Rx, size).map(Into::into)
    }

    #[inline]
    pub fn cr(&self, size: u32) -> Result<Consumer<u64>, anyhow::Error> {
        self.ring(RingKind::Complete, size).map(Into::into)
    }
}

#[repr(transparent)]
pub struct RingFlags(NonNull<u32>);

impl RingFlags {
    #[inline]
    pub fn needs_wakeup(&self) -> bool {
        (load_u32(self.0, Ordering::Relaxed) & XDP_RING_NEED_WAKEUP) != 0
    }
}

pub struct Ring<T> {
    cached_prod: u32,
    cached_cons: u32,

    size: u32,
    mask: StrengthReducedU32,

    ring: NonNull<T>,

    prod: NonNull<u32>,
    cons: NonNull<u32>,
    flags: NonNull<u32>,

    area: NonNull<[u8]>,
}

unsafe impl<T> Send for Ring<T> {}

impl<T> Ring<T> {
    #[inline]
    fn new(
        allocator: &RingAllocator,
        kind: RingKind,
        size: u32,
    ) -> Result<Self, anyhow::Error> {
        let off = allocator.offsets.get_offset(&kind);

        let len = off.desc as usize + size as usize * size_of::<T>();
        let raw_area = unsafe {
            mmap(
                null_mut(),
                len,
                PROT_READ | PROT_WRITE,
                (MmapFlags::Populate | MmapFlags::Shared).bits(),
                allocator.socket.as_raw_fd(),
                kind.get_page_offset(),
            )
        };

        cbail!(raw_area == MAP_FAILED => "allocating ring buffer");

        let area = NonNull::slice_from_raw_parts(
            unsafe { NonNull::new_unchecked(raw_area as *mut u8) },
            len,
        );

        let prod = unsafe {
            NonNull::new_unchecked(raw_area.add(off.producer as usize).cast())
        };

        let cons = unsafe {
            NonNull::new_unchecked(raw_area.add(off.consumer as usize).cast())
        };

        let (cached_prod, cached_cons) = match kind {
            RingKind::Fill => (0, size),
            RingKind::Complete => (0, 0),
            RingKind::Tx => (
                load_u32(prod, Ordering::Relaxed),
                load_u32(cons, Ordering::Relaxed) + size,
            ),
            RingKind::Rx => (
                load_u32(prod, Ordering::Relaxed),
                load_u32(cons, Ordering::Relaxed),
            ),
        };

        Ok(Self {
            cached_prod,
            cached_cons,

            size,
            mask: StrengthReducedU32::new(size),

            ring: unsafe {
                NonNull::new_unchecked(raw_area.add(off.desc as usize).cast())
            },

            prod,
            cons,
            flags: unsafe {
                NonNull::new_unchecked(raw_area.add(off.flags as usize).cast())
            },

            area,
        })
    }

    #[inline]
    pub const fn flags(&self) -> RingFlags {
        RingFlags(self.flags)
    }

    #[inline]
    pub const fn size(&self) -> u32 {
        self.size
    }
}

impl<T> Index<u32> for Ring<T> {
    type Output = T;

    #[inline]
    fn index(&self, index: u32) -> &Self::Output {
        unsafe { &*self.ring.as_ptr().add((index % self.mask) as usize) }
    }
}

impl<T> IndexMut<u32> for Ring<T> {
    #[inline]
    fn index_mut(&mut self, index: u32) -> &mut Self::Output {
        unsafe { &mut *self.ring.as_ptr().add((index % self.mask) as usize) }
    }
}

impl<T> Drop for Ring<T> {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            munmap(self.area.as_ptr() as *mut _, self.area.len());
        }
    }
}

#[repr(transparent)]
pub struct Producer<T>(Ring<T>);

impl<T> From<Ring<T>> for Producer<T> {
    #[inline]
    fn from(value: Ring<T>) -> Self {
        Self(value)
    }
}

//noinspection RsSuperTraitIsNotImplemented
impl<T> Deref for Producer<T> {
    type Target = Ring<T>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

//noinspection RsSuperTraitIsNotImplemented
impl<T> DerefMut for Producer<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> Producer<T> {
    #[inline]
    pub fn free(&mut self, batch_size: u32) -> u32 {
        let free_entries = self.0.cached_cons - self.0.cached_prod;
        if free_entries >= batch_size {
            return free_entries;
        }

        self.0.cached_cons =
            load_u32(self.0.cons, Ordering::Acquire) + self.0.size();

        self.0.cached_cons - self.0.cached_prod
    }

    #[inline]
    pub fn reserve(&mut self, batch_size: u32) -> Option<u32> {
        if self.free(batch_size) < batch_size {
            return None;
        }

        let index = self.0.cached_prod;
        self.0.cached_prod += batch_size;

        Some(index)
    }

    #[inline]
    pub fn submit(&self, batch_size: u32) -> u32 {
        fetch_add_u32(self.0.prod, batch_size, Ordering::Release)
    }
}

#[repr(transparent)]
pub struct Consumer<T>(Ring<T>);

impl<T> From<Ring<T>> for Consumer<T> {
    #[inline]
    fn from(value: Ring<T>) -> Self {
        Self(value)
    }
}

//noinspection RsSuperTraitIsNotImplemented
impl<T> Deref for Consumer<T> {
    type Target = Ring<T>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

//noinspection RsSuperTraitIsNotImplemented
impl<T> DerefMut for Consumer<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> Consumer<T> {
    #[inline]
    pub fn available(&mut self, batch_size: u32) -> u32 {
        let mut entries = self.0.cached_prod - self.0.cached_cons;
        if entries == 0 {
            self.0.cached_prod = load_u32(self.0.prod, Ordering::Acquire);
            entries = self.0.cached_prod - self.0.cached_cons;
        }

        u32::min(entries, batch_size)
    }

    #[inline]
    pub fn peek(&mut self, batch_size: u32) -> Option<u32> {
        let entries = self.available(batch_size);
        if entries > 0 {
            let index = self.0.cached_cons;
            self.0.cached_cons += entries;

            return Some(index);
        }

        None
    }

    #[inline]
    pub fn release(&self, batch_size: u32) -> u32 {
        fetch_add_u32(self.0.cons, batch_size, Ordering::Release)
    }
}
