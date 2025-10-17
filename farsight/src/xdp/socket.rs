use crate::{
    cbail,
    xdp::{ring::RingAllocator, umem::UmemReg},
};
use anyhow::Context;
use bitflags::bitflags;
use libc::{
    bind, getsockopt, recvfrom, sendto, setsockopt,
    sockaddr_xdp, socket, AF_XDP, MSG_DONTWAIT, PF_XDP, SOCK_CLOEXEC,
    SOCK_RAW, SOL_SOCKET, SOL_XDP, SO_BUSY_POLL,
    SO_BUSY_POLL_BUDGET, SO_PREFER_BUSY_POLL, XDP_COPY, XDP_SHARED_UMEM, XDP_UMEM_REG, XDP_USE_NEED_WAKEUP,
    XDP_USE_SG, XDP_ZEROCOPY,
};
use std::{
    io::Error,
    mem::MaybeUninit,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    ptr::null_mut,
    sync::Arc,
};

bitflags! {
    pub struct BindFlags: u16 {
        const NeedWakeup = XDP_USE_NEED_WAKEUP;
        const ZeroCopy = XDP_ZEROCOPY;
        const Copy = XDP_COPY;
        const SharedUmem = XDP_SHARED_UMEM;
        const UseSg = XDP_USE_SG;
    }
}

#[repr(transparent)]
#[derive(Clone)]
pub struct Socket(Arc<OwnedFd>);

impl Socket {
    #[inline]
    pub fn new() -> Result<Self, Error> {
        let fd = unsafe { socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0) };

        cbail!(fd < 0);

        Ok(Self(Arc::new(unsafe { OwnedFd::from_raw_fd(fd) })))
    }

    #[inline]
    pub(super) fn set_opt<T>(
        &self,
        level: i32,
        name: i32,
        value: &T,
    ) -> Result<(), Error> {
        let err = unsafe {
            setsockopt(
                self.0.as_raw_fd(),
                level,
                name,
                value as *const _ as *mut _,
                size_of::<T>() as _,
            )
        };

        cbail!(err != 0);
        Ok(())
    }

    #[inline]
    pub(super) fn get_opt<T>(&self, level: i32, name: i32) -> Result<T, Error> {
        let mut optlen = size_of::<T>() as _;
        let mut maybe = MaybeUninit::<T>::uninit();
        let err = unsafe {
            getsockopt(
                self.as_raw_fd(),
                level,
                name,
                maybe.as_mut_ptr() as *mut _,
                &raw mut optlen,
            )
        };

        cbail!(err != 0);
        Ok(unsafe { maybe.assume_init() })
    }

    #[inline]
    pub fn set_umem_reg(&self, umem_reg: &UmemReg) -> Result<(), Error> {
        self.set_opt(SOL_XDP, XDP_UMEM_REG, umem_reg)
    }

    #[inline]
    pub fn set_busy_poll(&self) -> Result<(), anyhow::Error> {
        self.set_opt(SOL_SOCKET, SO_PREFER_BUSY_POLL, &1i32)
            .context("setting so_prefer_busy_poll")?;
        self.set_opt(SOL_SOCKET, SO_BUSY_POLL, &1000i32)
            .context("setting so_prefer_busy_poll")?;
        self.set_opt(SOL_SOCKET, SO_BUSY_POLL_BUDGET, &8i32)
            .context("setting so_prefer_busy_poll")?;

        Ok(())
    }

    #[inline]
    pub fn rings(&'_ self) -> Result<RingAllocator<'_>, anyhow::Error> {
        RingAllocator::new(self)
    }

    #[inline]
    pub fn sendto(&self) -> Result<(), Error> {
        cbail!(
            unsafe {
                sendto(
                    self.as_raw_fd(),
                    null_mut(),
                    0,
                    MSG_DONTWAIT,
                    null_mut(),
                    0,
                )
            } < 0
        );

        Ok(())
    }

    #[inline]
    pub fn recvfrom(&self) -> Result<(), Error> {
        cbail!(
            unsafe {
                recvfrom(
                    self.as_raw_fd(),
                    null_mut(),
                    0,
                    MSG_DONTWAIT,
                    null_mut(),
                    null_mut(),
                )
            } < 0
        );

        Ok(())
    }

    #[inline]
    pub fn bind(
        &self,
        flags: BindFlags,
        if_index: u32,
        queue_id: u32,
        shared_umem_fd: u32,
    ) -> Result<(), Error> {
        let sxdp = sockaddr_xdp {
            sxdp_family: PF_XDP as _,
            sxdp_flags: flags.bits(),
            sxdp_ifindex: if_index,
            sxdp_queue_id: queue_id,
            sxdp_shared_umem_fd: shared_umem_fd,
        };

        cbail!(
            unsafe {
                bind(
                    self.as_raw_fd(),
                    &raw const sxdp as *const _,
                    size_of::<sockaddr_xdp>() as _,
                )
            } < 0
        );

        Ok(())
    }
}

impl AsRawFd for Socket {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
