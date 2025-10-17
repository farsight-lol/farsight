use crate::cbail;
use anyhow::{bail, Context};
use libc::{
    c_char, ifreq, ioctl, socket, AF_INET, AF_NETLINK,
    IFNAMSIZ, NETLINK_GENERIC, SIOCETHTOOL, SOCK_DGRAM, SOCK_RAW,
};
use std::{
    io::Error,
    mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    ptr,
    str::FromStr,
};

const ETHTOOL_GCHANNELS: u32 = 0x0000003c;

#[repr(C)]
#[derive(Default, Debug, Clone)]
pub struct Queues {
    cmd: u32,

    pub max: Queue,
    pub current: Queue,
}

#[repr(C)]
#[derive(Default, Debug, Clone)]
pub struct Queue {
    pub rx: u32,
    pub tx: u32,
    pub other: u32,
    pub combined: u32,
}

pub struct InterfaceInfoGuard {
    fd: OwnedFd,
    ifr: ifreq,
}

impl InterfaceInfoGuard {
    #[inline]
    pub fn new(dev: &str) -> Result<Self, anyhow::Error> {
        if dev.len() > IFNAMSIZ {
            bail!("interface name is too long")
        }

        let mut fd = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
        if fd < 0 {
            fd = unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC) };

            cbail!(fd < 0 => "creating control socket");
        }

        let mut ifr_name = [0 as c_char; IFNAMSIZ];
        unsafe {
            ptr::copy_nonoverlapping(
                dev.as_ptr(),
                &raw mut ifr_name as *mut c_char as *mut u8,
                dev.len(),
            );
        }

        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            ifr: ifreq {
                ifr_name,
                ifr_ifru: unsafe { mem::zeroed() },
            },
        })
    }

    #[inline]
    pub fn queues(&mut self) -> Result<Queues, Error> {
        let mut queues = Queues {
            cmd: ETHTOOL_GCHANNELS,
            ..Default::default()
        };

        self.ifr.ifr_ifru.ifru_data = &raw mut queues as *mut _;

        cbail!(
            unsafe {
                ioctl(self.fd.as_raw_fd(), SIOCETHTOOL, &raw const self.ifr)
            } < 0
        );

        Ok(queues)
    }
}
