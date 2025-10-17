use std::{
    mem,
    net::Ipv4Addr,
    ops::Range,
};
use std::ops::Deref;
use strength_reduce::StrengthReducedUsize;

pub type Address = (Ipv4Addr, u16);
pub type CompiledRanges = Ranges<Address, CompilationInfo, usize>;
pub type AddressRanges = Ranges<Address>;
pub type Ipv4Ranges = Ranges<Ipv4Addr>;
pub type PortRanges = Ranges<u16>;

pub struct CompilationInfo {
    port_count: StrengthReducedUsize,
    index: usize,
    count: usize,
}

#[derive(Default)]
pub struct Ranges<T, E = (), C = ()> {
    inner: Vec<(/* Inclusive */ Range<T>, E)>,
    count: C,
}

impl<T, E, C> Ranges<T, E, C> {
    #[inline]
    pub fn into_inner(self) -> Vec<(Range<T>, E)> {
        self.inner
    }
}

impl<T> From<Range<T>> for Ranges<T, (), ()> {
    #[inline]
    fn from(value: Range<T>) -> Self {
        Self {
            inner: vec![(value, ())],
            count: (),
        }
    }
}

impl<T> From<Vec<Range<T>>> for Ranges<T, (), ()> {
    #[inline]
    fn from(value: Vec<Range<T>>) -> Self {
        Self {
            inner: value.into_iter()
                .map(|range| (range, ()))
                .collect(),
            count: (),
        }
    }
}

impl AddressRanges {
    #[inline]
    pub fn exclude(&mut self, exclude_ranges: &Ipv4Ranges) {
        let mut exclude_ranges = exclude_ranges.inner.iter();
        let Some(exclude_range) = exclude_ranges.next() else {
            return;
        };

        let mut exclude_range = &exclude_range.0;

        let mut scan_ranges = mem::take(&mut self.inner).into_iter();
        let Some((mut scan_range, _)) = scan_ranges.next() else {
            return;
        };

        loop {
            if scan_range.end.0 < exclude_range.start {
                self.inner.push((scan_range, ()));

                match scan_ranges.next() {
                    Some((new_range, _)) => scan_range = new_range,
                    None => break,
                };
            } else if scan_range.start.0 > exclude_range.end {
                match exclude_ranges.next() {
                    Some((new_range, _)) => exclude_range = new_range,
                    None => {
                        self.inner.push((scan_range, ()));
                        break;
                    }
                };
            } else if scan_range.start.0 < exclude_range.start
                && scan_range.end.0 > exclude_range.end
            {
                let new_range = scan_range.start
                    ..(
                        Ipv4Addr::from(exclude_range.start.to_bits() - 1),
                        scan_range.end.1,
                    );
                self.inner.push((new_range, ()));

                scan_range.start.0 =
                    Ipv4Addr::from(u32::from(exclude_range.end) + 1);
            } else if scan_range.start.0 < exclude_range.start {
                self.inner.push((
                    scan_range.start
                        ..(
                            Ipv4Addr::from(exclude_range.start.to_bits() - 1),
                            scan_range.end.1,
                        ),
                    (),
                ));

                match scan_ranges.next() {
                    Some((new_range, _)) => scan_range = new_range,
                    None => break,
                };
            } else if scan_range.end.0 > exclude_range.end {
                scan_range.start.0 =
                    Ipv4Addr::from(exclude_range.end.to_bits() + 1);
            } else {
                match scan_ranges.next() {
                    Some((new_range, _)) => scan_range = new_range,
                    None => break,
                };
            }
        }

        self.inner.extend(scan_ranges);
    }

    #[inline]
    pub fn compile(self) -> CompiledRanges {
        let mut ranges = Vec::with_capacity(self.inner.len());
        let mut index = 0;
        for (range, _) in self.inner {
            let port_count = range.end.1 as usize - range.start.1 as usize + 1;
            let count = (
                range.end.0.to_bits() as usize
                - range.start.0.to_bits() as usize
                + 1
            ) * port_count;

            ranges.push((
                range,
                CompilationInfo {
                    port_count: StrengthReducedUsize::new(port_count),
                    count,
                    index,
                },
            ));

            index += count;
        }

        Ranges {
            inner: ranges,
            count: index,
        }
    }
}

impl CompiledRanges {
    #[inline]
    pub const fn count(&self) -> usize {
        self.count
    }

    #[inline]
    pub fn index(&self, index: usize) -> Address {
        let mut start = 0;
        let mut end = self.inner.len();
        while start < end {
            let mid = (start + end) / 2;

            // SAFETY: guaranteed to be in range, no need for checks
            let range = unsafe { self.inner.get_unchecked(mid) };

            if range.1.index + range.1.count <= index {
                start = mid + 1;
            } else if range.1.index > index {
                end = mid;
            } else {
                // modulus & division at the same time + faster
                let (addr, port) = StrengthReducedUsize::div_rem(
                    index - range.1.index,
                    range.1.port_count,
                );

                return (
                    Ipv4Addr::from_bits(
                        (range.0.start.0.to_bits() as usize + addr) as u32,
                    ),
                    range.0.start.1 + port as u16,
                );
            }
        }

        panic!("index out of bounds");
    }
}
