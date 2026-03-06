#[derive(Debug, Clone)]
pub struct StabilizerEngine {
    ewma_rate_pps: f64,
    smoothing: f64,
}

impl Default for StabilizerEngine {
    fn default() -> Self {
        Self {
            ewma_rate_pps: 0.0,
            smoothing: 0.72,
        }
    }
}

impl StabilizerEngine {
    pub fn stabilize_rate(&mut self, requested_rate_pps: u64, multiplier: f64) -> u64 {
        let target = (requested_rate_pps as f64 * multiplier).max(1.0);
        if self.ewma_rate_pps <= 0.0 {
            self.ewma_rate_pps = target;
        } else {
            self.ewma_rate_pps =
                self.ewma_rate_pps * self.smoothing + target * (1.0 - self.smoothing);
        }
        self.ewma_rate_pps.max(1.0) as u64
    }
}
