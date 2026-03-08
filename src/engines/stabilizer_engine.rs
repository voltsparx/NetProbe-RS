#[derive(Debug, Clone)]
pub struct StabilizerEngine {
    ewma_rate_pps: f64,
    smoothing: f64,
    max_step_up: f64,
    max_step_down: f64,
    min_rate_floor: u64,
}

impl Default for StabilizerEngine {
    fn default() -> Self {
        Self {
            ewma_rate_pps: 0.0,
            smoothing: 0.78,
            max_step_up: 0.20,
            max_step_down: 0.35,
            min_rate_floor: 1,
        }
    }
}

impl StabilizerEngine {
    #[allow(dead_code)]
    pub fn stabilize_rate(&mut self, requested_rate_pps: u64, multiplier: f64) -> u64 {
        self.stabilize_rate_with_feedback(requested_rate_pps, multiplier, 0.0, 0.0)
    }

    pub fn stabilize_rate_with_feedback(
        &mut self,
        requested_rate_pps: u64,
        multiplier: f64,
        packet_drop_ratio: f64,
        timeout_pressure: f64,
    ) -> u64 {
        let drop_ratio = packet_drop_ratio.clamp(0.0, 1.0);
        let timeout_ratio = timeout_pressure.clamp(0.0, 1.0);

        let pressure_penalty = (drop_ratio * 0.45) + (timeout_ratio * 0.35);
        let target = (requested_rate_pps.max(self.min_rate_floor) as f64
            * multiplier.clamp(0.20, 2.0)
            * (1.0 - pressure_penalty).clamp(0.35, 1.10))
        .max(self.min_rate_floor as f64);

        let previous = if self.ewma_rate_pps <= 0.0 {
            target
        } else {
            self.ewma_rate_pps
        };

        if self.ewma_rate_pps <= 0.0 {
            self.ewma_rate_pps = target;
        } else {
            self.ewma_rate_pps =
                self.ewma_rate_pps * self.smoothing + target * (1.0 - self.smoothing);
        }

        let adaptive_up = self.max_step_up * (1.0 - (drop_ratio * 0.6 + timeout_ratio * 0.7));
        let up_limit =
            previous * (1.0 + adaptive_up.clamp(self.max_step_up * 0.20, self.max_step_up));

        let adaptive_down = self.max_step_down * (0.25 + ((drop_ratio + timeout_ratio) * 0.50));
        let down_limit =
            previous * (1.0 - adaptive_down.clamp(self.max_step_down * 0.20, self.max_step_down));

        let stabilized = self
            .ewma_rate_pps
            .clamp(down_limit.max(self.min_rate_floor as f64), up_limit)
            .max(self.min_rate_floor as f64);

        self.ewma_rate_pps = stabilized;
        stabilized.round() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::StabilizerEngine;

    #[test]
    fn rate_stabilizer_limits_spike_growth() {
        let mut stabilizer = StabilizerEngine::default();
        let first = stabilizer.stabilize_rate(100_000, 1.0);
        let second = stabilizer.stabilize_rate(100_000, 2.0);
        assert!(second > first);
        assert!(second <= (first as f64 * 1.25) as u64);
    }

    #[test]
    fn pressure_forces_backoff() {
        let mut stabilizer = StabilizerEngine::default();
        let baseline = stabilizer.stabilize_rate(120_000, 1.0);
        let stressed = stabilizer.stabilize_rate_with_feedback(120_000, 1.0, 0.30, 0.50);
        assert!(stressed < baseline);
    }
}
