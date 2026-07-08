// forked from https://github.com/cppcoffee/hugepage-rs

use std::fs::File;
use std::io::Read;
use std::sync::LazyLock;
use libc::{sysconf, _SC_PAGESIZE};

pub(crate) static HUGEPAGE_SIZE: LazyLock<usize> = LazyLock::new(|| {
    let mut buf = String::new();
    if let Ok(mut f) = File::open("/proc/meminfo") {
        _ = f.read_to_string(&mut buf);
    }

    parse_hugepage_size(&buf)
        .expect("failed to parse hugepage size from /proc/meminfo")
});

fn parse_hugepage_size(s: &str) -> Option<usize> {
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("Hugepagesize:") {
            let mut parts = rest.split_whitespace();

            let size = parts.next()?.parse::<usize>().ok()?;
            let multiplier = match parts.next() {
                None => 1,
                Some("kB") => 1024,
                Some(_) => return None,
            };

            return Some(size * multiplier);
        }
    }

    None
}

pub(crate) static PAGE_SIZE: LazyLock<usize> = LazyLock::new(|| {
    unsafe { sysconf(_SC_PAGESIZE) as usize }
});

#[inline(always)]
pub(crate) fn align_to_hugepage(size: usize) -> usize {
    let align = *HUGEPAGE_SIZE;

    align_to(size, align)
}

#[inline(always)]
pub(crate) fn align_to_page(size: usize) -> usize {
    let align = *PAGE_SIZE;

    align_to(size, align)
}

#[inline(always)]
fn align_to(size: usize, align: usize) -> usize {
    (size + align - 1) & !(align - 1)
}

