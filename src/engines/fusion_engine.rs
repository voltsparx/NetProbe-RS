use crate::engines::intelligence_engine::{IntelligenceEngine, PacketIntelligenceInput};
use crate::engines::packet_crafter::PacketCrafterRegistry;
use crate::engines::parallel_threads_engine::{ParallelThreadsEngine, ParallelThreadsPlan};
use crate::engines::stabilizer_engine::StabilizerEngine;

#[derive(Debug, Clone, Copy)]
pub struct PacketFusionInput {
    pub requested_rate_pps: u64,
    pub operator_rate_locked: bool,
    pub gpu_rate_cap_pps: Option<u64>,
    pub burst_size: usize,
    pub target_count: usize,
    pub max_tx_workers: usize,
    pub max_tx_batch_size: usize,
    pub max_window_size: usize,
    pub atomic_mode: bool,
    pub packet_drop_ratio: f64,
    pub timeout_pressure: f64,
    pub response_ratio: f64,
    pub queue_pressure: f64,
    pub retry_pressure: f64,
}

#[derive(Debug, Clone, Copy)]
pub struct PacketFusionPlan {
    pub effective_rate_pps: u64,
    pub tx_workers: usize,
    pub tx_batch_size: usize,
    pub window_size: usize,
    pub rate_multiplier: f64,
    pub situation: &'static str,
    pub active_crafters: usize,
}

#[derive(Debug, Clone)]
pub struct FusionEngine {
    intelligence: IntelligenceEngine,
    stabilizer: StabilizerEngine,
    parallel: ParallelThreadsEngine,
    crafters: PacketCrafterRegistry,
}

impl Default for FusionEngine {
    fn default() -> Self {
        Self {
            intelligence: IntelligenceEngine,
            stabilizer: StabilizerEngine::default(),
            parallel: ParallelThreadsEngine,
            crafters: PacketCrafterRegistry::default(),
        }
    }
}

impl FusionEngine {
    pub fn plan(&mut self, input: PacketFusionInput) -> PacketFusionPlan {
        if input.atomic_mode {
            let atomic_multiplier = if input.operator_rate_locked {
                1.0
            } else {
                0.82
            };
            let atomic_rate = self.stabilizer.stabilize_rate_with_feedback(
                input.requested_rate_pps.max(1),
                atomic_multiplier,
                input.packet_drop_ratio,
                input.timeout_pressure,
            );
            return PacketFusionPlan {
                effective_rate_pps: atomic_rate,
                tx_workers: 1,
                tx_batch_size: 1,
                window_size: input.max_window_size.max(1).min(input.target_count.max(1)),
                rate_multiplier: atomic_multiplier,
                situation: if input.operator_rate_locked {
                    "operator-locked-atomic"
                } else {
                    "atomic"
                },
                active_crafters: self.crafters.active_count(),
            };
        }

        let mut decision = self.intelligence.decide(PacketIntelligenceInput {
            requested_rate_pps: input.requested_rate_pps,
            target_count: input.target_count,
            packet_drop_ratio: input.packet_drop_ratio,
            timeout_pressure: input.timeout_pressure,
            response_ratio: input.response_ratio,
            queue_pressure: input.queue_pressure,
            retry_pressure: input.retry_pressure,
        });
        if input.operator_rate_locked {
            decision.rate_multiplier = decision.rate_multiplier.min(1.0);
            decision.worker_bias = decision.worker_bias.min(0);
            decision.batch_bias = decision.batch_bias.min(0);
        }

        let mut effective_rate_pps = self.stabilizer.stabilize_rate_with_feedback(
            input.requested_rate_pps,
            decision.rate_multiplier,
            input.packet_drop_ratio,
            input.timeout_pressure,
        );
        if let Some(gpu_rate_cap_pps) = input.gpu_rate_cap_pps.filter(|value| *value > 0) {
            effective_rate_pps = effective_rate_pps.min(gpu_rate_cap_pps);
        }

        let ParallelThreadsPlan {
            mut tx_workers,
            mut tx_batch_size,
        } = self.parallel.plan(
            effective_rate_pps,
            input.burst_size,
            input.target_count,
            decision.worker_bias,
            decision.batch_bias,
        );

        tx_workers = tx_workers.min(input.max_tx_workers.max(1)).max(1);
        tx_batch_size = tx_batch_size.min(input.max_tx_batch_size.max(1)).max(1);

        let window_size = tx_workers
            .saturating_mul(tx_batch_size)
            .saturating_mul(4)
            .max(1)
            .min(input.max_window_size.max(1))
            .min(input.target_count.max(1));

        PacketFusionPlan {
            effective_rate_pps,
            tx_workers,
            tx_batch_size,
            window_size,
            rate_multiplier: decision.rate_multiplier,
            situation: if input.operator_rate_locked {
                match decision.situation {
                    crate::engines::intelligence_engine::SituationLevel::Stable => {
                        "operator-locked"
                    }
                    crate::engines::intelligence_engine::SituationLevel::Pressured => {
                        "operator-locked-pressured"
                    }
                    crate::engines::intelligence_engine::SituationLevel::Congested => {
                        "operator-locked-congested"
                    }
                }
            } else {
                decision.situation.as_str()
            },
            active_crafters: self.crafters.active_count(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FusionEngine, PacketFusionInput};

    #[test]
    fn atomic_mode_forces_single_packet_cadence() {
        let mut engine = FusionEngine::default();
        let plan = engine.plan(PacketFusionInput {
            requested_rate_pps: 25,
            operator_rate_locked: false,
            gpu_rate_cap_pps: None,
            burst_size: 1,
            target_count: 6,
            max_tx_workers: 1,
            max_tx_batch_size: 1,
            max_window_size: 1,
            atomic_mode: true,
            packet_drop_ratio: 0.0,
            timeout_pressure: 0.0,
            response_ratio: 0.0,
            queue_pressure: 0.0,
            retry_pressure: 0.0,
        });
        assert_eq!(plan.tx_workers, 1);
        assert_eq!(plan.tx_batch_size, 1);
        assert_eq!(plan.window_size, 1);
        assert!(plan.effective_rate_pps <= 25);
    }

    #[test]
    fn operator_locked_mode_never_scales_above_requested_rate() {
        let mut engine = FusionEngine::default();
        let plan = engine.plan(PacketFusionInput {
            requested_rate_pps: 500,
            operator_rate_locked: true,
            gpu_rate_cap_pps: None,
            burst_size: 64,
            target_count: 4_096,
            max_tx_workers: 16,
            max_tx_batch_size: 64,
            max_window_size: 256,
            atomic_mode: false,
            packet_drop_ratio: 0.0,
            timeout_pressure: 0.0,
            response_ratio: 0.95,
            queue_pressure: 0.0,
            retry_pressure: 0.0,
        });
        assert!(plan.effective_rate_pps <= 500);
        assert!(plan.situation.starts_with("operator-locked"));
    }
}
