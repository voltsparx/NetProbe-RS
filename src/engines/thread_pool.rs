use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use dns_lookup::lookup_addr;

use crate::error::{NetProbeError, NetProbeResult};

pub async fn resolve_target(target: &str) -> NetProbeResult<Vec<IpAddr>> {
    let input = target.to_string();
    let mut ips = tokio::task::spawn_blocking(move || -> std::io::Result<Vec<IpAddr>> {
        let mut dedupe = HashSet::new();
        let mut resolved = Vec::new();
        for addr in (input.as_str(), 0).to_socket_addrs()? {
            if dedupe.insert(addr.ip()) {
                resolved.push(addr.ip());
            }
        }
        Ok(resolved)
    })
    .await??;

    if ips.is_empty() {
        return Err(NetProbeError::Parse(format!(
            "could not resolve target '{}'",
            target
        )));
    }
    ips.sort();
    Ok(ips)
}

pub async fn reverse_lookup(ip: IpAddr) -> Option<String> {
    let task = tokio::task::spawn_blocking(move || lookup_addr(&ip).ok());
    match tokio::time::timeout(Duration::from_millis(1200), task).await {
        Ok(joined) => joined.ok().flatten(),
        Err(_) => None,
    }
}

pub async fn write_output(path: &Path, body: &str) -> NetProbeResult<()> {
    let output_path = path.to_path_buf();
    let content = body.to_string();
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(output_path, content)
    })
    .await??;

    Ok(())
}
