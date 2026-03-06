// Legacy compatibility shim plus async dispatch helper for packet engines.

use std::io;

#[allow(unused_imports)]
pub use crate::engine_async::scanner::*;

#[derive(Debug, Default, Clone, Copy)]
pub struct AsyncPacketEngine;

impl AsyncPacketEngine {
    pub async fn run_blocking<F, T>(label: &'static str, work: F) -> io::Result<T>
    where
        F: FnOnce() -> io::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        tokio::task::spawn_blocking(work)
            .await
            .map_err(|err| io::Error::other(format!("{label} worker failed: {err}")))?
    }
}
