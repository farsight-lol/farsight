use fxhash::FxHashMap;
use rand::RngExt;

pub struct PrefixGraph {
    historical_hits: FxHashMap<u32, u64>,
}

impl PrefixGraph {
    #[inline]
    pub fn from_counts(historical_hits: FxHashMap<u32, u64>) -> Self {
        Self { historical_hits }
    }

    #[inline]
    pub fn historical_score(&self, prefix_id: u32) -> u64 {
        self.historical_hits.get(&prefix_id).copied().unwrap_or(0)
    }
}

pub struct PrefixState {
    bitmap: [u8; 32],
    pub remaining: u16,
}

impl PrefixState {
    #[inline]
    pub fn new() -> Self {
        Self { bitmap: [0; 32], remaining: 256 }
    }

    #[inline]
    fn is_unscanned(&self, offset: u8) -> bool {
        (self.bitmap[(offset / 8) as usize] >> (offset % 8)) & 1 != 1
    }

    #[inline]
    pub fn mark_scanned(&mut self, offset: u8) -> bool {
        let byte = &mut self.bitmap[(offset / 8) as usize];
        let bit = 1 << (offset % 8);

        if *byte & bit != 0 {
            true
        } else {
            *byte |= bit;
            self.remaining -= 1;

            false
        }
    }

    #[inline]
    pub fn fetch_unscanned(&self, rng: &mut impl rand::Rng) -> Option<u8> {
        if self.remaining == 0 {
            return None;
        }

        for _ in 0..50 {
            let candidate = rng.random_range(0u16..256) as u8;
            if self.is_unscanned(candidate) {
                return Some(candidate);
            }
        }

        (0u8..=255u8)
            .find(|&o| self.is_unscanned(o))
    }
}