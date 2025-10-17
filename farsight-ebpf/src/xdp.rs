#![no_std]
#![no_main]

use core::mem::MaybeUninit;
use core::ptr;
use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_ebpf::bindings::sk_action::{SK_DROP, SK_PASS};
use aya_ebpf::bindings::xdp_action::{XDP_ABORTED, XDP_DROP, XDP_PASS};
use aya_ebpf::macros::{map, sk_msg};
use aya_ebpf::maps::{RingBuf, SockMap, XskMap};
use aya_ebpf::programs::SkMsgContext;
use aya_log_ebpf::{error, info, trace};
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::tcp::TcpHdr;

#[map]
static SOCKS: XskMap = XskMap::with_max_entries(128, 0);

#[unsafe(no_mangle)]
static SOURCE_PORT_START: u16 = 0;

#[unsafe(no_mangle)]
static SOURCE_PORT_END: u16 = 0;

#[xdp]
pub fn farsight_xdp(ctx: XdpContext) -> u32 {
    unsafe { try_farsight_xdp(&ctx) }.unwrap_or_else(|()| {
        error!(&ctx, "aborting program...");

        XDP_ABORTED
    })
}

#[inline(always)]
unsafe fn try_farsight_xdp(ctx: &XdpContext) -> Result<u32, ()> {
    let source_port_start = unsafe { ptr::read_volatile(&SOURCE_PORT_START) };
    if source_port_start == 0 {
        error!(ctx, "source port start has not been set!");
        
        return Err(());
    }

    let source_port_end = unsafe { ptr::read_volatile(&SOURCE_PORT_END) };
    if source_port_end == 0 {
        error!(ctx, "source port end has not been set!");

        return Err(());
    }

    let ethhdr = ptr_at::<EthHdr>(ctx, 0)?;
    if unsafe { (*ethhdr).ether_type } != EtherType::Ipv4 {
        // only interested in ipv4
        return Ok(XDP_PASS)
    }

    let ipv4hdr = ptr_at::<Ipv4Hdr>(ctx, EthHdr::LEN)?;
    if unsafe { (*ipv4hdr).proto } != IpProto::Tcp {
        // only interested in tcp
        return Ok(XDP_PASS);
    }

    let tcphdr = ptr_at::<TcpHdr>(ctx, EthHdr::LEN + 4 * unsafe { (*ipv4hdr).ihl() } as usize)?;
    let dest = unsafe { (*tcphdr).dest };

    if dest < source_port_start || dest > source_port_end {
        // not sent by us
        return Ok(XDP_PASS);
    }

    SOCKS.redirect(
        ctx.rx_queue_index(),
        0
    ).or(Ok(XDP_PASS))
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    let addr = start + offset;
    if addr + size_of::<T>() > end {
        return Err(());
    }

    Ok(addr as *const T)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::hint::unreachable_unchecked()
    }
}
