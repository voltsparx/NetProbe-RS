// Blocking token bucket for packet TX loops.

use std::thread;
use std::time::{Duration, Instant};

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

    pub fn acquire_blocking(&mut self, permits: u64) {
        if self.rate_per_sec == 0 || permits == 0 {
            return;
        }

        let wanted = permits as f64;
        loop {
            self.refill();
            if self.tokens >= wanted {
                self.tokens -= wanted;
                return;
            }

            let missing = (wanted - self.tokens).max(0.01);
            let wait_secs = missing / self.rate_per_sec as f64;
            let wait = Duration::from_secs_f64(wait_secs)
                .clamp(Duration::from_micros(200), Duration::from_millis(50));
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
    use super::TokenBucket;
    use std::time::Instant;

    #[test]
    fn zero_rate_is_unlimited() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(0, 1);
        bucket.acquire_blocking(1000);
        assert!(start.elapsed().as_millis() < 10);
    }
}
