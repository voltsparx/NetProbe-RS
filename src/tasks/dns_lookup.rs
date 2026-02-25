use std::net::IpAddr;

use crate::engines::thread_pool;
use crate::error::NetProbeResult;

pub async fn resolve(target: &str) -> NetProbeResult<Vec<IpAddr>> {
    thread_pool::resolve_target(target).await
}

pub async fn reverse(ip: IpAddr) -> Option<String> {
    thread_pool::reverse_lookup(ip).await
}
