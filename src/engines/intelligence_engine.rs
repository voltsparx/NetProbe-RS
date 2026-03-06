#[derive(Debug, Clone, Copy)]
pub struct PacketIntelligenceInput {
    pub requested_rate_pps: u64,
    pub target_count: usize,
    pub packet_drop_ratio: f64,
    pub timeout_pressure: f64,
    pub response_ratio: f64,
    pub queue_pressure: f64,
    pub retry_pressure: f64,
}

impl PacketIntelligenceInput {
    fn normalized(self) -> Self {
        Self {
            requested_rate_pps: self.requested_rate_pps.max(1),
            target_count: self.target_count.max(1),
            packet_drop_ratio: self.packet_drop_ratio.clamp(0.0, 1.0),
            timeout_pressure: self.timeout_pressure.clamp(0.0, 1.0),
            response_ratio: self.response_ratio.clamp(0.0, 1.0),
            queue_pressure: self.queue_pressure.clamp(0.0, 1.0),
            retry_pressure: self.retry_pressure.clamp(0.0, 1.0),
        }
    }
}

impl Default for PacketIntelligenceInput {
    fn default() -> Self {
        Self {
            requested_rate_pps: 10_000,
            target_count: 1,
            packet_drop_ratio: 0.0,
            timeout_pressure: 0.0,
            response_ratio: 0.0,
            queue_pressure: 0.0,
            retry_pressure: 0.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SituationLevel {
    Stable,
    Pressured,
    Congested,
}

impl SituationLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            SituationLevel::Stable => "stable",
            SituationLevel::Pressured => "pressured",
            SituationLevel::Congested => "congested",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PacketIntelligenceDecision {
    pub rate_multiplier: f64,
    pub worker_bias: i32,
    pub batch_bias: i32,
    pub situation: SituationLevel,
}

#[derive(Debug, Default, Clone)]
pub struct IntelligenceEngine;

impl IntelligenceEngine {
    pub fn decide(&self, input: PacketIntelligenceInput) -> PacketIntelligenceDecision {
        let input = input.normalized();

        let congestion_score = input.packet_drop_ratio * 1.9
            + input.timeout_pressure * 1.5
            + input.queue_pressure * 1.2
            + input.retry_pressure * 0.8;
        let recovery_score = input.response_ratio * 0.7;
        let pressure = (congestion_score - recovery_score).clamp(0.0, 1.5);

        let situation = if pressure >= 0.95 {
            SituationLevel::Congested
        } else if pressure >= 0.45 {
            SituationLevel::Pressured
        } else {
            SituationLevel::Stable
        };

        let mut rate_multiplier: f64 = match situation {
            SituationLevel::Stable => 1.08_f64,
            SituationLevel::Pressured => 0.82_f64,
            SituationLevel::Congested => 0.58_f64,
        };
        if input.packet_drop_ratio >= 0.25 || input.timeout_pressure >= 0.50 {
            rate_multiplier *= 0.86;
        }
        if input.response_ratio >= 0.80
            && input.packet_drop_ratio <= 0.03
            && input.timeout_pressure <= 0.10
        {
            rate_multiplier *= 1.04;
        }
        if input.target_count < 128 {
            rate_multiplier = rate_multiplier.min(1.0);
        }
        if input.requested_rate_pps >= 600_000 {
            // At very high configured rates, only allow modest upward moves.
            rate_multiplier = rate_multiplier.min(1.04);
        }

        let mut worker_bias = match situation {
            SituationLevel::Stable => 1,
            SituationLevel::Pressured => -1,
            SituationLevel::Congested => -2,
        };
        let mut batch_bias = match situation {
            SituationLevel::Stable => 1,
            SituationLevel::Pressured => -1,
            SituationLevel::Congested => -2,
        };

        if input.target_count >= 65_536 && !matches!(situation, SituationLevel::Congested) {
            worker_bias += 1;
            batch_bias += 1;
        }
        if input.queue_pressure >= 0.35 {
            worker_bias -= 1;
            batch_bias -= 1;
        }
        if input.requested_rate_pps <= 20_000 {
            worker_bias = worker_bias.min(0);
            batch_bias = batch_bias.min(0);
        }

        PacketIntelligenceDecision {
            rate_multiplier: rate_multiplier.clamp(0.40, 1.25),
            worker_bias: worker_bias.clamp(-3, 3),
            batch_bias: batch_bias.clamp(-3, 3),
            situation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{IntelligenceEngine, PacketIntelligenceInput, SituationLevel};

    #[test]
    fn stable_conditions_scale_up_carefully() {
        let engine = IntelligenceEngine;
        let decision = engine.decide(PacketIntelligenceInput {
            requested_rate_pps: 80_000,
            target_count: 4096,
            packet_drop_ratio: 0.01,
            timeout_pressure: 0.02,
            response_ratio: 0.95,
            queue_pressure: 0.01,
            retry_pressure: 0.02,
        });
        assert_eq!(decision.situation, SituationLevel::Stable);
        assert!(decision.rate_multiplier > 1.0);
    }

    #[test]
    fn congested_conditions_back_off_hard() {
        let engine = IntelligenceEngine;
        let decision = engine.decide(PacketIntelligenceInput {
            requested_rate_pps: 120_000,
            target_count: 4096,
            packet_drop_ratio: 0.30,
            timeout_pressure: 0.55,
            response_ratio: 0.05,
            queue_pressure: 0.40,
            retry_pressure: 0.45,
        });
        assert_eq!(decision.situation, SituationLevel::Congested);
        assert!(decision.rate_multiplier < 0.7);
        assert!(decision.worker_bias < 0);
    }
}
