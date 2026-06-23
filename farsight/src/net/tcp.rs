use std::marker::ConstParamTy;
use bitflags::bitflags;
use std::net::Ipv4Addr;
use zerocopy::{network_endian, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub static TCP_PACKET: [u8; 62] = [
    // ETHER : [0..14]
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // (dst mac) : [0..6]
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // (src mac) : [6..12]
    0x08,
    0x00, // proto
    // IP : [14..34]
    0x45, // version = 4 & header len = 5 (20 bytes)
    0x00, // dsf - unimportant
    0x00,
    0x30, // total length = 48
    0x00,
    0x01, // identification - unimportant
    0b010_00000,
    0x00, // flags = don't fragment & fragment offset = 0
    0x40, // ttl = 64
    0x06, // protocol = TCP (6)
    0x00,
    0x00, // [checksum] : [24..26]
    0,
    0,
    0,
    0, // [src ip] : [26..30]
    0,
    0,
    0,
    0, // [dst ip] : [30..34]
    // TCP : [34..62]
    0x00,
    0x00, // [src port] : [34..36]
    0x00,
    0x00, // [dst port] : [36..38]
    0x00,
    0x00,
    0x00,
    0x00, // [sequence number] : [38..42]
    0x00,
    0x00,
    0x00,
    0x00,       // [acknowledgment number] : [42..46]
    0x70,       // data offset
    0b00000000, // flags : 47
    0x80,
    0x00, // window size = 32768
    0x00,
    0x00, // [checksum] : [50..52]
    0x00,
    0x00, // urgent pointer = 0
    // TCP OPTIONS
    0x02,
    0x04,
    0x05,
    0x3C, // mss: 1340
    0x01,
    0x01, // nop + nop
    0x04,
    0x02, // sack-perm
];

// minimal (with some fields hidden) struct for writing fields to the packet above
// since apparently it's faster than direct byte writes
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct EthTcpIpHdr {
    _padding_0: [u8; 16],
    pub len: network_endian::U16,
    _padding_1: [u8; 6],
    pub ip_checksum: network_endian::U16,
    _padding_2: [u8; 4],
    pub dest_addr: [u8; 4],

    pub source_port: network_endian::U16,
    pub dest_port: network_endian::U16,
    pub seq: network_endian::U32,
    pub ack: network_endian::U32,
    _padding_3: u8,
    pub flags: TcpFlags,
    _padding_4: [u8; 2],
    pub tcp_checksum: network_endian::U16,
}

// same thing here
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
pub struct TcpHdr {
    pub source_port: network_endian::U16,
    pub dest_port: network_endian::U16,
    pub seq: network_endian::U32,
    pub ack: network_endian::U32,
    _padding: u8,
    pub flags: TcpFlags,
}

#[derive(IntoBytes, FromBytes, Immutable, KnownLayout, Unaligned, Eq, PartialEq, Debug, ConstParamTy)]
#[repr(transparent)]
pub struct TcpFlags(u8);

bitflags! {
    impl TcpFlags: u8 {
        const Fin = 0b00000001;
        const Syn = 0b00000010;
        const Rst = 0b00000100;
        const Psh = 0b00001000;
        const Ack = 0b00010000;
        const Urg = 0b00100000;
        const Ece = 0b01000000;
        const Cwr = 0b10000000;
    }
}

const K: usize = 0xf1357aea2e62a9c5;

#[inline(always)]
pub const fn cookie(ip: &Ipv4Addr, port: u16, seed: u64) -> u32 {
    (u32::from_ne_bytes(ip.octets()) as usize)
        .wrapping_mul(K)
        .wrapping_add(port as usize)
        .wrapping_mul(K)
        .wrapping_add(seed as usize)
        .wrapping_mul(K) as u32
}

#[inline(always)]
pub const fn ipv4_sum(ip: &[u8; 4]) -> u32 {
    u16::from_be_bytes([ip[0], ip[1]]) as u32
        + u16::from_be_bytes([ip[2], ip[3]]) as u32
}

#[inline(always)]
pub const fn fold(sum: u32) -> u16 {
    let sum = (sum >> 16) + (sum & 0xffff);
    (sum + (sum >> 16)) as u16
}

#[inline]
pub fn sum_body(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }

    sum
}
