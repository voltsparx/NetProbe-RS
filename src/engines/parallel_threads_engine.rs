use std::thread;

#[derive(Debug, Clone, Copy)]
pub struct ParallelThreadsPlan {
    pub tx_workers: usize,
    pub tx_batch_size: usize,
}

#[derive(Debug, Default, Clone)]
pub struct ParallelThreadsEngine;

impl ParallelThreadsEngine {
    pub fn plan(
        &self,
        effective_rate_pps: u64,
        burst_size: usize,
        target_count: usize,
        worker_bias: i32,
        batch_bias: i32,
    ) -> ParallelThreadsPlan {
        let cpu = thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(4)
            .clamp(1, 32);

        let base_workers = if effective_rate_pps >= 320_000 {
            8
        } else if effective_rate_pps >= 160_000 {
            4
        } else if effective_rate_pps >= 60_000 {
            2
        } else {
            1
        };

        let workers = (base_workers + worker_bias)
            .clamp(1, cpu as i32)
            .min(target_count.max(1) as i32) as usize;

        let base_batch = if effective_rate_pps >= 320_000 {
            256
        } else if effective_rate_pps >= 160_000 {
            128
        } else if effective_rate_pps >= 60_000 {
            64
        } else {
            16
        };

        let batch = (base_batch + (batch_bias * 16)).clamp(8, 512) as usize;

        ParallelThreadsPlan {
            tx_workers: workers.max(1),
            tx_batch_size: batch.min(burst_size.max(1)),
        }
    }
}
