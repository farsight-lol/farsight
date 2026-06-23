use crate::{
    controller::sender::Sender,
};
use std::{net::Ipv4Addr, thread};
use std::time::{Duration, Instant};
use crate::controller::completer::Completer;
use crate::controller::strategy::port::PortAdapter;

pub(super) struct Scanner<'umem: 'b, 'b, A: PortAdapter> {
    adapter: &'b A,
    
    targets: Vec<(u16, Ipv4Addr, u16)>,

    tokens: f64,
    last_refill: Instant,

    sender: Sender<'umem>,
    rate: f64,
    
    seed: u64
}

impl<'umem: 'b, 'b, A: PortAdapter> Scanner<'umem, 'b, A> {
    #[inline]
    pub(super) fn new(
        sender: Sender<'umem>,
        adapter: &'b A,
        seed: u64
    ) -> Self {
        Self {
            adapter,

            targets: Vec::with_capacity(sender.shared.config.xdp.ring_size as usize),

            tokens: 0f64,
            last_refill: Instant::now(),

            rate: sender.shared.per_scanner_rate,
            sender,
            
            seed
        }
    }

    #[inline]
    pub(super) fn tick(&mut self, completer: &mut Completer) -> Option<anyhow::Error> {
        self.targets.clear();

        let mut taken = 0;

        let batch = self.next_batch();
        for _ in 0..batch {
            match self.adapter.pop() {
                Some(target) => {
                    taken += 1;
                    self.targets.push(target)
                },
                None => break,
            }
        }

        if taken < batch {
            self.tokens += (batch - taken) as f64;

            if taken == 0 {
                thread::sleep(Duration::from_micros(100));
            }
        }

        self.sender.send_syn_batch(&self.targets, self.seed, completer).err()
    }

    #[inline]
    fn next_batch(&mut self) -> u64 {
        let rate = self.rate;
        loop {
            let now = Instant::now();
            let elapsed = now.duration_since(self.last_refill).as_secs_f64();
            self.last_refill = now;

            self.tokens = (self.tokens + elapsed * rate).min(self.targets.capacity() as f64);

            if self.tokens < 1.0 {
                let need = 1.0 - self.tokens;
                let wait = (need / rate).min(0.1);

                thread::sleep(Duration::from_secs_f64(wait));

                continue;
            }

            let take = self.tokens.floor();
            self.tokens -= take;

            return take as u64;
        }
    }

    #[inline]
    pub(super) fn into_inner(self) -> Sender<'umem> {
        self.sender
    }
}
