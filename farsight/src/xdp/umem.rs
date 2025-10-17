use anyhow::{bail, Context};
use libc::{xsk_tx_metadata, XDP_UMEM_TX_METADATA_LEN};
use std::alloc::{alloc_zeroed, dealloc, Layout};

pub const TX_METADATA_LEN: usize = size_of::<xsk_tx_metadata>();

pub struct Umem {
    area: *mut u8,
    layout: Layout,

    frame_size: u32,
}

// i hereby promise that i
// wont concurrently make writes
// to the same part of umem
unsafe impl Send for Umem {}
unsafe impl Sync for Umem {}

impl Umem {
    #[inline]
    pub fn new(
        frame_size: u32,
        frame_count: u32,
    ) -> Result<Self, anyhow::Error> {
        let layout =
            Layout::from_size_align((frame_size * frame_count) as usize, 16384)
                .context("creating umem layout")?;

        let area = unsafe { alloc_zeroed(layout) };
        if area.is_null() {
            bail!("allocating umem area")
        }

        Ok(Self {
            area,
            layout,

            frame_size,
        })
    }

    #[inline]
    pub fn as_ptr(&self) -> *mut u8 {
        self.area
    }

    #[inline]
    pub fn size(&self) -> usize {
        self.layout.size()
    }

    #[inline]
    pub fn frame_size(&self) -> u32 {
        self.frame_size
    }

    #[inline]
    pub fn as_reg(&self) -> UmemReg {
        UmemReg {
            addr: self.area as u64,
            len: self.layout.size() as u64,
            frame_size: self.frame_size,
            headroom: 0,
            flags: XDP_UMEM_TX_METADATA_LEN,
            tx_metadata_len: TX_METADATA_LEN as u32,
        }
    }
}

impl Drop for Umem {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            dealloc(self.area, self.layout);
        }
    }
}

#[repr(C)]
#[derive(Default)]
pub struct UmemReg {
    addr: u64,
    len: u64,
    frame_size: u32,
    headroom: u32,
    flags: u32,
    tx_metadata_len: u32,
}

impl UmemReg {
    #[inline]
    pub const fn remove_flags(&mut self) {
        self.flags = 0;
    }
}
