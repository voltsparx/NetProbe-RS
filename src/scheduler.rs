// Flow sketch: input -> core processing -> output model
// Pseudo-block:
//   read input -> process safely -> return deterministic output

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
#[cfg(unix)]
use std::process::Command;

use chrono::Utc;
use futures::future::join_all;

use crate::engines::lua_engine;
use crate::error::{NetProbeError, NetProbeResult};
use crate::fingerprint_db::FingerprintDatabase;
use crate::models::{
    EngineStats, HostResult, KnowledgeStats, ScanMetadata, ScanReport, ScanRequest,
    ScanRequestSummary,
};
use crate::service_db::ServiceRegistry;
use crate::tasks;

const MAX_RESOLVED_HOSTS: usize = 16;

struct HostExecution {
    host: HostResult,
    async_tasks: usize,
    thread_pool_tasks: usize,
    parallel_tasks: usize,
    lua_hooks_ran: bool,
}

pub async fn run_scan(mut request: ScanRequest) -> NetProbeResult<ScanReport> {
    let started = Utc::now();
    let mut thread_pool_tasks = 0usize;

    let service_registry = Arc::new(ServiceRegistry::load());
    let resolved = tasks::dns_lookup::resolve(&request.target).await?;
    thread_pool_tasks += 1;

    let mut global_warnings = Vec::new();
    enforce_safety(&mut request, &resolved, &mut global_warnings)?;
    enforce_privileged_modes(&mut request, &mut global_warnings)?;

    let selected_ports = if request.ports.is_empty() {
        let top = request.top_ports.unwrap_or(100);
        service_registry.top_tcp_ports(top)
    } else {
        request.ports.clone()
    };
    if selected_ports.is_empty() {
        return Err(NetProbeError::Parse(
            "no ports selected for scanning".to_string(),
        ));
    }

    let fingerprint_db = if request.service_detection {
        Arc::new(FingerprintDatabase::load_for_ports(
            &selected_ports,
            request.include_udp,
        ))
    } else {
        Arc::new(FingerprintDatabase::empty())
    };

    let host_targets: Vec<IpAddr> = if resolved.len() > MAX_RESOLVED_HOSTS {
        global_warnings.push(format!(
            "resolved {} addresses; scanning first {}",
            resolved.len(),
            MAX_RESOLVED_HOSTS
        ));
        resolved.into_iter().take(MAX_RESOLVED_HOSTS).collect()
    } else {
        resolved
    };

    let mut jobs = Vec::with_capacity(host_targets.len());
    for ip in host_targets {
        jobs.push(process_host(
            request.clone(),
            ip,
            selected_ports.clone(),
            global_warnings.clone(),
            service_registry.clone(),
            fingerprint_db.clone(),
        ));
    }

    let mut hosts = Vec::new();
    let mut async_tasks = 0usize;
    let mut parallel_tasks = 0usize;
    let mut lua_hooks_ran = false;

    for result in join_all(jobs).await {
        let execution = result?;
        async_tasks += execution.async_tasks;
        thread_pool_tasks += execution.thread_pool_tasks;
        parallel_tasks += execution.parallel_tasks;
        lua_hooks_ran = lua_hooks_ran || execution.lua_hooks_ran;
        hosts.push(execution.host);
    }

    let finished = Utc::now();
    let fp_stats = fingerprint_db.stats();
    let report = ScanReport {
        metadata: ScanMetadata {
            started_at: started,
            finished_at: finished,
            duration_ms: (finished - started).num_milliseconds(),
            engine_stats: EngineStats {
                async_engine_tasks: async_tasks,
                thread_pool_tasks,
                parallel_tasks,
                lua_hooks_ran,
            },
            knowledge: KnowledgeStats {
                services_loaded: service_registry.service_count(),
                ranked_tcp_ports: service_registry.ranked_port_count(),
                probe_payloads_loaded: fp_stats.payloads_loaded,
                fingerprint_rules_loaded: fp_stats.rules_loaded,
                fingerprint_rules_compiled: fp_stats.rules_compiled,
                fingerprint_rules_skipped: fp_stats.rules_skipped,
                nse_scripts_seen: fp_stats.nse_scripts,
                nselib_modules_seen: fp_stats.nselib_modules,
            },
        },
        request: ScanRequestSummary {
            target: request.target.clone(),
            port_count: selected_ports.len(),
            include_udp: request.include_udp,
            explain: request.explain,
            verbose: request.verbose,
            profile: request.profile,
            root_only: request.root_only,
            aggressive_root: request.aggressive_root,
            privileged_probes: request.effective_privileged_probes(),
            report_format: request.report_format,
            lab_mode: request.lab_mode,
        },
        hosts,
    };

    tasks::reporting::run(
        &report,
        request.report_format,
        request.output_path.as_deref(),
    )
    .await?;
    Ok(report)
}

async fn process_host(
    request: ScanRequest,
    ip: IpAddr,
    selected_ports: Vec<u16>,
    global_warnings: Vec<String>,
    service_registry: Arc<ServiceRegistry>,
    fingerprint_db: Arc<FingerprintDatabase>,
) -> NetProbeResult<HostExecution> {
    let (mut host, async_tasks) = tasks::port_scan::run(
        &request,
        ip,
        selected_ports,
        service_registry,
        fingerprint_db,
    )
    .await?;
    host.warnings.extend(global_warnings);

    let mut thread_pool_tasks = 0usize;
    if request.reverse_dns {
        if let Some(reverse_dns) = tasks::dns_lookup::reverse(ip).await {
            host.reverse_dns = Some(reverse_dns);
            thread_pool_tasks += 1;
        }
    }

    let parallel_tasks = tasks::analysis::run(&mut host, request.explain);
    let lua_findings = lua_engine::run(&host, request.lua_script.as_deref())?;
    host.lua_findings = lua_findings;
    if !host.lua_findings.is_empty() {
        host.insights.push(format!(
            "lua hooks added {} custom findings",
            host.lua_findings.len()
        ));
    }

    Ok(HostExecution {
        host,
        async_tasks,
        thread_pool_tasks,
        parallel_tasks,
        lua_hooks_ran: true,
    })
}

fn enforce_safety(
    request: &mut ScanRequest,
    resolved_ips: &[IpAddr],
    warnings: &mut Vec<String>,
) -> NetProbeResult<()> {
    let has_public_targets = resolved_ips.iter().any(|ip| !is_private_or_local(ip));
    if request.lab_mode && has_public_targets {
        return Err(NetProbeError::Safety(
            "lab mode allows only private/local target addresses".to_string(),
        ));
    }

    if has_public_targets {
        warnings.push(
            "external target detected: ensure documented authorization before scanning".to_string(),
        );

        if !request.allow_external {
            warnings.push(
                "no --allow-external flag supplied: applying conservative network limits"
                    .to_string(),
            );
            apply_conservative_limits(request);
            if request.strict_safety {
                return Err(NetProbeError::Safety(
                    "strict safety is enabled and external targets were detected without --allow-external"
                        .to_string(),
                ));
            }
        }
    }

    if request.lab_mode {
        warnings.push("lab mode active: scan constrained to private/local targets".to_string());
    }

    Ok(())
}

fn enforce_privileged_modes(
    request: &mut ScanRequest,
    warnings: &mut Vec<String>,
) -> NetProbeResult<()> {
    if !request.requires_root() {
        return Ok(());
    }

    if !has_root_privileges() {
        return Err(NetProbeError::Safety(build_root_required_message(request)));
    }

    warnings.push("root capability detected: privileged scan extensions enabled".to_string());

    if request.root_only {
        apply_root_only_limits(request);
        warnings
            .push("root-only preset active: mobile-tuned limits applied for stability".to_string());
    }

    if request.aggressive_root {
        request.include_udp = true;
        request.service_detection = true;
        warnings.push(
            "aggressive-root active: forcing UDP probes and service fingerprinting".to_string(),
        );
    }

    Ok(())
}

fn apply_conservative_limits(request: &mut ScanRequest) {
    let defaults = request.profile.defaults();
    let base_concurrency = request.concurrency.unwrap_or(defaults.concurrency);
    let base_delay = request.delay_ms.unwrap_or(defaults.delay_ms);
    let base_timeout = request.timeout_ms.unwrap_or(defaults.timeout_ms);

    request.concurrency = Some(base_concurrency.min(96));
    request.delay_ms = Some(base_delay.max(15));
    request.timeout_ms = Some(base_timeout.max(1000));
}

fn apply_root_only_limits(request: &mut ScanRequest) {
    let defaults = crate::models::ScanProfile::RootOnly.defaults();
    let base_concurrency = request.concurrency.unwrap_or(defaults.concurrency);
    let base_delay = request.delay_ms.unwrap_or(defaults.delay_ms);
    let base_timeout = request.timeout_ms.unwrap_or(defaults.timeout_ms);

    request.concurrency = Some(base_concurrency.clamp(16, 192));
    request.delay_ms = Some(base_delay.max(3));
    request.timeout_ms = Some(base_timeout.max(900));
}

fn is_private_or_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

fn is_private_v4(ip: &Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
}

fn is_private_v6(ip: &Ipv6Addr) -> bool {
    ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local() || ip.is_unspecified()
}

fn has_root_privileges() -> bool {
    #[cfg(unix)]
    {
        if let Some(uid) = std::env::var_os("EUID").or_else(|| std::env::var_os("UID")) {
            if uid.to_string_lossy().trim() == "0" {
                return true;
            }
        }

        if let Ok(output) = Command::new("id").arg("-u").output() {
            if output.status.success() {
                return String::from_utf8_lossy(&output.stdout).trim() == "0";
            }
        }

        false
    }

    #[cfg(not(unix))]
    {
        false
    }
}

fn build_root_required_message(request: &ScanRequest) -> String {
    let mut modes = Vec::new();
    if request.aggressive_root {
        modes.push("--aggressive-root");
    }
    if request.privileged_probes {
        modes.push("--privileged-probes");
    }

    let mode_text = modes.join(", ");
    if is_termux_env() {
        format!(
            "{mode_text} requires root in Termux. Re-run inside a root shell (for example via `su`) and retry."
        )
    } else {
        format!("{mode_text} requires root/admin privileges. Re-run with sudo or equivalent.")
    }
}

fn is_termux_env() -> bool {
    if std::env::var_os("TERMUX_VERSION").is_some() {
        return true;
    }

    std::env::var_os("PREFIX")
        .map(|value| {
            value
                .to_string_lossy()
                .to_ascii_lowercase()
                .contains("com.termux")
        })
        .unwrap_or(false)
}

