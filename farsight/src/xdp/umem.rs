use crate::xdp::ring::Descriptor;
use anyhow::{bail, Context};
use libc::{mmap, munmap, xsk_tx_metadata, MAP_ANONYMOUS, MAP_FAILED, MAP_HUGETLB, MAP_PRIVATE, PROT_READ, PROT_WRITE, XDP_UMEM_TX_METADATA_LEN};
use std::{
    alloc::{alloc_zeroed, dealloc, Layout},
    slice::from_raw_parts_mut,
};
use std::ptr::null_mut;
use log::info;
use crate::xdp::page::{align_to_hugepage, align_to_page};
use crate::xdp::socket::Socket;
use crate::xdp::tx_metadata::TxMetadata;

pub struct Umem {
    area: *mut u8,
    size: usize,

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
        huge_pages: bool,
    ) -> Result<Self, anyhow::Error> {
        let size;

        let mut flags = MAP_PRIVATE | MAP_ANONYMOUS;
        if huge_pages {
            size = align_to_hugepage(frame_size.saturating_mul(frame_count) as usize);
            flags |= MAP_HUGETLB;
        } else {
            size = align_to_page(frame_size.saturating_mul(frame_count) as usize);
        }

        let area = unsafe {
            mmap(
                null_mut(),
                size,
                PROT_WRITE | PROT_READ,
                flags,
                -1,
                0
            )
        };

        if area == MAP_FAILED {
            bail!("allocating umem area")
        }

        Ok(Self {
            area: area as *mut _,
            size,

            frame_size,
        })
    }

    #[inline]
    #[allow(clippy::mut_from_ref)] // guaranteed by our rings that aliasing is impossible
    pub fn of_desc(&self, desc: &Descriptor) -> &mut [u8] {
        unsafe {
            from_raw_parts_mut(
                self.area.add(desc.addr as usize),
                self.frame_size as usize,
            )
        }
    }

    #[inline]
    pub fn as_ptr(&self) -> *mut u8 {
        self.area
    }

    #[inline]
    pub fn frame_size(&self) -> u32 {
        self.frame_size
    }

    #[inline]
    pub fn as_reg(&self) -> UmemReg {
        UmemReg {
            addr: self.area as u64,
            len: self.size as u64,
            frame_size: self.frame_size,
            headroom: 0,
            flags: XDP_UMEM_TX_METADATA_LEN,
            tx_metadata_len: TxMetadata::LEN as u32,
        }
    }

    #[inline]
    pub fn bind(&self, socket: Socket) -> anyhow::Result<()> {
        let mut reg = self.as_reg();
        socket.set_umem_reg(&reg)
            .or_else(|_| {
                info!("error setting umem reg, retrying - this may occur with some kernels");

                reg.remove_flags();
                socket.set_umem_reg(&reg)
            })
            .context("setting umem reg")?;

        Ok(())
    }
}

impl Drop for Umem {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            munmap(self.area as *mut _, self.size);
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
