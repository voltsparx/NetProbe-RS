// Blocking token bucket for packet TX loops.

use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, Default)]
struct RateBucket {
    timestamp_us: u64,
    packet_count: u64,
}

// Masscan-style adaptive throttler: estimates recent rate and adjusts batch size.
#[derive(Debug, Clone)]
pub struct AdaptiveThrottler {
    max_rate: f64,
    batch_size: f64,
    index: u64,
    buckets: [RateBucket; 256],
    started: Instant,
}

impl AdaptiveThrottler {
    pub fn new(max_rate: u64) -> Self {
        let mut throttler = Self {
            max_rate: max_rate as f64,
            batch_size: 1.0,
            index: 0,
            buckets: [RateBucket::default(); 256],
            started: Instant::now(),
        };
        let now = throttler.now_us();
        for bucket in &mut throttler.buckets {
            bucket.timestamp_us = now;
            bucket.packet_count = 0;
        }
        throttler
    }

    pub fn next_batch(&mut self, packet_count: u64, max_batch: u64) -> u64 {
        if max_batch == 0 {
            return 0;
        }
        if self.max_rate <= 0.0 {
            return max_batch;
        }

        loop {
            let timestamp = self.now_us();
            let now_index = (self.index & 0xff) as usize;
            self.buckets[now_index].timestamp_us = timestamp;
            self.buckets[now_index].packet_count = packet_count;

            self.index = self.index.wrapping_add(1);
            let old_index = (self.index & 0xff) as usize;
            let old_bucket = self.buckets[old_index];

            if timestamp <= old_bucket.timestamp_us {
                self.batch_size = 1.0;
                return 1;
            }

            let elapsed_us = timestamp - old_bucket.timestamp_us;
            if elapsed_us > 1_000_000 {
                self.batch_size = 1.0;
                continue;
            }

            let current_rate = (packet_count.saturating_sub(old_bucket.packet_count) as f64)
                / (elapsed_us as f64 / 1_000_000.0);

            if current_rate > self.max_rate {
                let mut wait_secs = (current_rate - self.max_rate) / self.max_rate;
                wait_secs *= 0.10;
                if wait_secs > 0.10 {
                    wait_secs = 0.10;
                }
                self.batch_size *= 0.999;
                if wait_secs > 0.0 {
                    thread::sleep(Duration::from_secs_f64(wait_secs));
                } else {
                    thread::yield_now();
                }
                continue;
            }

            self.batch_size *= 1.005;
            if self.batch_size > 10_000.0 {
                self.batch_size = 10_000.0;
            }
            let batch = self.batch_size as u64;
            return batch.clamp(1, max_batch);
        }
    }

    fn now_us(&self) -> u64 {
        self.started.elapsed().as_micros() as u64
    }
}

#[derive(Debug, Clone)]
pub struct TokenBucket {
    rate_per_sec: u64,
    capacity: f64,
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(rate_per_sec: u64, burst: usize) -> Self {
        let capacity = burst.max(1) as f64;
        Self {
            rate_per_sec,
            capacity,
            tokens: capacity,
            last_refill: Instant::now(),
        }
    }

    pub fn acquire_batch_blocking(&mut self, max_permits: u64) -> u64 {
        if max_permits == 0 {
            return 0;
        }
        if self.rate_per_sec == 0 {
            return max_permits;
        }

        loop {
            self.refill();
            if self.tokens >= 1.0 {
                let ready = self.tokens.floor() as u64;
                let granted = ready.clamp(1, max_permits);
                self.tokens -= granted as f64;
                return granted;
            }

            let missing = (1.0 - self.tokens).max(0.01);
            let wait_secs = missing / self.rate_per_sec as f64;
            let wait = Duration::from_secs_f64(wait_secs)
                .clamp(Duration::from_micros(100), Duration::from_millis(50));
            thread::sleep(wait);
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last_refill);
        self.last_refill = now;

        if elapsed.is_zero() || self.rate_per_sec == 0 {
            return;
        }

        let added = elapsed.as_secs_f64() * self.rate_per_sec as f64;
        self.tokens = (self.tokens + added).min(self.capacity);
    }
}

#[cfg(test)]
mod tests {
    use super::{AdaptiveThrottler, TokenBucket};
    use std::time::Instant;

    #[test]
    fn zero_rate_is_unlimited() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(0, 1);
        let granted = bucket.acquire_batch_blocking(1000);
        assert_eq!(granted, 1000);
        assert!(start.elapsed().as_millis() < 10);
    }

    #[test]
    fn batch_acquire_returns_available_tokens() {
        let mut bucket = TokenBucket::new(1_000, 8);
        let first = bucket.acquire_batch_blocking(8);
        assert!(first >= 1);
        assert!(first <= 8);
    }

    #[test]
    fn adaptive_throttler_returns_positive_batch() {
        let mut throttler = AdaptiveThrottler::new(10_000);
        let batch = throttler.next_batch(0, 64);
        assert!(batch >= 1);
        assert!(batch <= 64);
    }
}
