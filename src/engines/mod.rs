// Flow sketch: scan request -> probe engine -> raw findings
// Pseudo-block:
//   read input -> process safely -> return deterministic output

pub mod async_engine;
pub mod lua_engine;
pub mod parallel;
pub mod thread_pool;
