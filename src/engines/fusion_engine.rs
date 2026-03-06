use crate::engines::intelligence_engine::{IntelligenceEngine, PacketIntelligenceInput};
use crate::engines::packet_crafter::PacketCrafterRegistry;
use crate::engines::parallel_threads_engine::{ParallelThreadsEngine, ParallelThreadsPlan};
use crate::engines::stabilizer_engine::StabilizerEngine;

#[derive(Debug, Clone, Copy)]
pub struct PacketFusionInput {
    pub requested_rate_pps: u64,
    pub burst_size: usize,
    pub target_count: usize,
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
        let decision = self.intelligence.decide(PacketIntelligenceInput {
            requested_rate_pps: input.requested_rate_pps,
            target_count: input.target_count,
            packet_drop_ratio: input.packet_drop_ratio,
            timeout_pressure: input.timeout_pressure,
            response_ratio: input.response_ratio,
            queue_pressure: input.queue_pressure,
            retry_pressure: input.retry_pressure,
        });

        let effective_rate_pps = self.stabilizer.stabilize_rate_with_feedback(
            input.requested_rate_pps,
            decision.rate_multiplier,
            input.packet_drop_ratio,
            input.timeout_pressure,
        );

        let ParallelThreadsPlan {
            tx_workers,
            tx_batch_size,
        } = self.parallel.plan(
            effective_rate_pps,
            input.burst_size,
            input.target_count,
            decision.worker_bias,
            decision.batch_bias,
        );
        let window_size = tx_workers
            .saturating_mul(tx_batch_size)
            .saturating_mul(4)
            .clamp(64, 4096)
            .min(input.target_count.max(1));

        PacketFusionPlan {
            effective_rate_pps,
            tx_workers,
            tx_batch_size,
            window_size,
            rate_multiplier: decision.rate_multiplier,
            situation: decision.situation.as_str(),
            active_crafters: self.crafters.active_count(),
        }
    }
}
