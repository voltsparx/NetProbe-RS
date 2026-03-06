#[derive(Debug, Clone, Copy)]
pub struct PacketIntelligenceInput {
    pub requested_rate_pps: u64,
    pub target_count: usize,
    pub packet_drop_ratio: f64,
    pub timeout_pressure: f64,
}

#[derive(Debug, Clone, Copy)]
pub struct PacketIntelligenceDecision {
    pub rate_multiplier: f64,
    pub worker_bias: i32,
    pub batch_bias: i32,
}

#[derive(Debug, Default, Clone)]
pub struct IntelligenceEngine;

impl IntelligenceEngine {
    pub fn decide(&self, input: PacketIntelligenceInput) -> PacketIntelligenceDecision {
        let mut rate_multiplier = 1.0f64;
        let mut worker_bias = 0;
        let mut batch_bias = 0;

        // Back off quickly when drops/timeouts are high.
        if input.packet_drop_ratio >= 0.15 || input.timeout_pressure >= 0.35 {
            rate_multiplier *= 0.70;
            worker_bias -= 1;
            batch_bias -= 1;
        } else if input.packet_drop_ratio >= 0.06 || input.timeout_pressure >= 0.18 {
            rate_multiplier *= 0.85;
            batch_bias -= 1;
        } else {
            // Scale up conservatively on healthy paths.
            rate_multiplier *= 1.08;
            worker_bias += 1;
            batch_bias += 1;
        }

        if input.target_count >= 65_536 {
            worker_bias += 1;
            batch_bias += 1;
        }

        if input.requested_rate_pps <= 20_000 {
            worker_bias = worker_bias.min(0);
            batch_bias = batch_bias.min(0);
        }

        PacketIntelligenceDecision {
            rate_multiplier: rate_multiplier.clamp(0.50, 1.35),
            worker_bias,
            batch_bias,
        }
    }
}
