use std::{
    mem,
    net::Ipv4Addr
    ,
    range::RangeInclusive,
};
use std::hash::Hash;

pub type CompiledRanges = Ranges<u32, CompilationInfo, usize>;
pub type Ipv4Ranges = Ranges<Ipv4Addr>;

pub struct CompilationInfo {
    index: usize,
    count: usize,
}

#[derive(Default)]
pub struct Ranges<T, E = (), C = ()> {
    inner: Vec<(RangeInclusive<T>, E)>,
    count: C,
}

impl<T, E, C> Ranges<T, E, C> {
    #[inline]
    pub fn into_inner(self) -> Vec<(RangeInclusive<T>, E)> {
        self.inner
    }
}

impl<T> From<Vec<T>> for Ranges<T, (), ()> where T: Hash + Eq + Clone {
    #[inline]
    fn from(value: Vec<T>) -> Self {
        Self {
            inner: value.into_iter()
                .map(|t| (RangeInclusive {
                    start: t.clone(),
                    last: t
                }, ()))
                .collect(),
            count: (),
        }
    }
}

impl<T> From<std::ops::RangeInclusive<T>> for Ranges<T, (), ()> {
    #[inline]
    fn from(value: std::ops::RangeInclusive<T>) -> Self {
        Self {
            inner: vec![(RangeInclusive::from(value), ())],
            count: (),
        }
    }
}

impl<T> From<Vec<std::ops::RangeInclusive<T>>> for Ranges<T, (), ()> {
    #[inline]
    fn from(value: Vec<std::ops::RangeInclusive<T>>) -> Self {
        Self {
            inner: value
                .into_iter()
                .map(|range| (RangeInclusive::from(range), ()))
                .collect(),
            count: (),
        }
    }
}

impl Ipv4Ranges {
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
            if scan_range.last < exclude_range.start {
                self.inner.push((scan_range, ()));

                match scan_ranges.next() {
                    Some((new_range, _)) => scan_range = new_range,
                    None => break,
                };
            } else if scan_range.start > exclude_range.last {
                match exclude_ranges.next() {
                    Some((new_range, _)) => exclude_range = new_range,
                    None => {
                        self.inner.push((scan_range, ()));
                        break;
                    }
                };
            } else if scan_range.start < exclude_range.start
                && scan_range.last > exclude_range.last
            {
                let new_range = RangeInclusive {
                    start: scan_range.start,
                    last: Ipv4Addr::from(exclude_range.start.to_bits() - 1),
                };

                self.inner.push((new_range, ()));

                scan_range.start =
                    Ipv4Addr::from(u32::from(exclude_range.last) + 1);
            } else if scan_range.start < exclude_range.start {
                let new_range = RangeInclusive {
                    start: scan_range.start,
                    last: Ipv4Addr::from(exclude_range.start.to_bits() - 1),
                };

                self.inner.push((new_range, ()));

                match scan_ranges.next() {
                    Some((new_range, _)) => scan_range = new_range,
                    None => break,
                };
            } else if scan_range.last > exclude_range.last {
                scan_range.start = Ipv4Addr::from(exclude_range.last.to_bits() + 1);
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
            let count = range.last.to_bits() as usize
                - range.start.to_bits() as usize
                + 1;

            let range = RangeInclusive {
                start: range.start.to_bits(),
                last: range.last.to_bits(),
            };

            ranges.push((
                range,
                CompilationInfo {
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
    #[inline(always)]
    pub const fn count(&self) -> usize {
        self.count
    }

    #[inline]
    pub fn index(&self, index: usize) -> u32 {
        let mut start = 0;
        let mut end = self.inner.len();
        
        while start < end {
            let mid = (start + end) / 2;

            // SAFETY: guaranteed to be in range
            let range = unsafe { self.inner.get_unchecked(mid) };

            if range.1.index + range.1.count <= index {
                start = mid + 1;
            } else if range.1.index > index {
                end = mid;
            } else {
                let addr = (index - range.1.index) as u32;

                return range.0.start + addr;
            }
        }

        panic!("index out of bounds");
    }
}
