// Flow sketch: scan request -> probe engine -> raw findings
// Pseudo-block:
//   read input -> process safely -> return deterministic output

pub mod async_engine;
pub mod fusion_engine;
pub mod intelligence_engine;
pub mod lua_engine;
pub mod packet_crafter;
pub mod parallel;
pub mod parallel_threads_engine;
pub mod stabilizer_engine;
pub mod thread_pool;
