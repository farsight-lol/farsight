use crate::{cbail, net::mac::MacAddr};
use anyhow::Context;
use core::slice;
use libc::{
    freeifaddrs, getifaddrs, if_nametoindex, ifaddrs, sockaddr, sockaddr_in,
    strlen, AF_INET,
};
use std::{
    ffi::CString,
    fs::read_to_string,
    io,
    marker::PhantomData,
    mem,
    mem::MaybeUninit,
    net::Ipv4Addr,
};

#[derive(Debug)]
pub struct IfAddr<'a> {
    pub name: &'a str,
    pub addr: Option<Ipv4Addr>,
}

pub struct IfAddrs<'a> {
    ifaddrs: *mut ifaddrs,
    next: *mut ifaddrs,
    _phantom: PhantomData<&'a ifaddrs>,
}

impl IfAddrs<'_> {
    #[inline]
    pub fn new() -> Result<Self, io::Error> {
        let mut ifaddrs = MaybeUninit::<*mut ifaddrs>::uninit();
        cbail!(unsafe { getifaddrs(ifaddrs.as_mut_ptr()) } < 0);

        let ifaddrs = unsafe { ifaddrs.assume_init() };

        Ok(Self {
            ifaddrs,
            next: ifaddrs,
            _phantom: PhantomData,
        })
    }
}

impl<'a> Iterator for IfAddrs<'a> {
    type Item = IfAddr<'a>;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        if self.next.is_null() {
            return None;
        }

        let ifaddrs = unsafe { &*self.next };
        let addr = unsafe { &*ifaddrs.ifa_addr };

        let addr: Option<Ipv4Addr> = if addr.sa_family == AF_INET as u16 {
            Some(Ipv4Addr::from_octets(
                unsafe { mem::transmute::<&sockaddr, &sockaddr_in>(addr) }
                    .sin_addr
                    .s_addr
                    .to_ne_bytes(),
            ))
        } else {
            None
        };

        let ifaddr = IfAddr {
            name: unsafe {
                str::from_utf8_unchecked(slice::from_raw_parts(
                    ifaddrs.ifa_name.cast(),
                    strlen(ifaddrs.ifa_name),
                ))
            },
            addr,
        };

        self.next = ifaddrs.ifa_next;

        Some(ifaddr)
    }
}

impl Drop for IfAddrs<'_> {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            freeifaddrs(self.ifaddrs);
        }
    }
}

pub fn get_mac(name: &str) -> Result<MacAddr, anyhow::Error> {
    let content = read_to_string(format!("/sys/class/net/{name}/address"))
        .context("reading mac")?;

    content.trim().try_into().context("parsing mac")
}

pub fn name_to_index(name: &str) -> Result<u32, io::Error> {
    let cname = CString::new(name)?;
    let if_index = unsafe { if_nametoindex(cname.as_ptr()) };

    cbail!(if_index == 0);

    Ok(if_index)
}
