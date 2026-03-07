// Flow sketch: input -> core processing -> output model
// Pseudo-block:
//   read input -> process safely -> return deterministic output

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
#[cfg(unix)]
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use futures::stream::{FuturesUnordered, StreamExt};

use crate::config::{self, ShardCheckpointArgs, ShardCheckpointState};
use crate::core::stop_signal;
use crate::engine_async::port_scan as async_port_scan;
use crate::engine_intel::{
    analysis,
    strategy::{self, ExecutionMode, ScanStrategy},
};
use crate::engine_packet::{arp as packet_arp, port_scan as packet_port_scan};
use crate::engine_parallel::dns;
use crate::engine_plugin::lua;
use crate::engine_report::reporting;
use crate::engines::scan_bundle;
use crate::error::{NProbeError, NProbeResult};
use crate::fetchers::{self, FetcherReport};
use crate::fingerprint_db::FingerprintDatabase;
use crate::models::{
    EngineStats, HostResult, KnowledgeStats, ScanMetadata, ScanProfile, ScanReport, ScanRequest,
    ScanRequestSummary,
};
use crate::platform::capability_registry;
use crate::service_db::ServiceRegistry;

const MAX_RESOLVED_HOSTS: usize = 16;
const MAX_CIDR_HOSTS: usize = 4096;
const PORT_BATCH_SIZE: usize = 256;
const MAX_PUBLIC_HOSTS: usize = 32;
const MAX_PUBLIC_PORTS: usize = 128;
const MAX_DEFENSIVE_PORTS: usize = 512;
const UNIVERSAL_PROTECTED_PORTS: &[u16] = &[9100];

struct ScanWorkItem {
    checkpoint_unit: String,
    ip: IpAddr,
    ports: Vec<u16>,
}

struct HostExecution {
    checkpoint_unit: String,
    host: HostResult,
    async_tasks: usize,
    thread_pool_tasks: usize,
    parallel_tasks: usize,
    lua_hooks_ran: bool,
}

struct ShardCheckpointRuntime {
    signature: String,
    unit_label: String,
    planned_units: Vec<String>,
    completed_units: HashSet<String>,
    resumed_units: usize,
}

type ShardingSelection = (Vec<IpAddr>, Vec<u16>, &'static str, u16, u16);

pub async fn run_scan(mut request: ScanRequest) -> NProbeResult<ScanReport> {
    let started = Utc::now();
    let mut thread_pool_tasks = 0usize;

    let service_registry = Arc::new(ServiceRegistry::load());
    let mut global_warnings = Vec::new();
    let resolved = resolve_targets(&request, &mut global_warnings).await?;
    thread_pool_tasks += 1;
    let has_public_targets = resolved.iter().any(|ip| !is_private_or_local(ip));
    let public_target_policy_applied = has_public_targets && request.allow_external;

    enforce_safety(&mut request, &resolved, &mut global_warnings)?;
    enforce_defensive_scope(&mut request, &resolved, &mut global_warnings)?;
    enforce_privileged_modes(&mut request, &mut global_warnings)?;

    let mut selected_ports = if request.ports.is_empty() {
        let top = request.top_ports.unwrap_or(100);
        service_registry.top_tcp_ports(top)
    } else {
        request.ports.clone()
    };
    apply_defensive_port_policy(
        &request,
        has_public_targets,
        &mut selected_ports,
        &mut global_warnings,
    )?;
    if selected_ports.is_empty() {
        return Err(NProbeError::Parse(
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

    let max_resolved_hosts = if packet_arp::parse_ipv4_cidr(&request.target).is_some() {
        MAX_CIDR_HOSTS
    } else {
        MAX_RESOLVED_HOSTS
    };
    let host_targets: Vec<IpAddr> = if resolved.len() > max_resolved_hosts {
        global_warnings.push(format!(
            "resolved {} addresses; scanning first {}",
            resolved.len(),
            max_resolved_hosts
        ));
        resolved.into_iter().take(max_resolved_hosts).collect()
    } else {
        resolved
    };

    let (host_targets, selected_ports, shard_dimension, total_shards, shard_index) =
        apply_sharding(host_targets, selected_ports, &request, &mut global_warnings)?;
    let (work_items, mut checkpoint_runtime) = prepare_shard_checkpoint(
        &request,
        host_targets,
        &selected_ports,
        total_shards,
        shard_index,
        shard_dimension,
        &mut global_warnings,
    )?;

    let strategy = strategy::plan(&request, work_items.len(), selected_ports.len());
    if !request.profile_explicit {
        request.profile = match strategy.mode {
            ExecutionMode::Async => {
                if request.strict_safety || request.lab_mode {
                    ScanProfile::Stealth
                } else {
                    ScanProfile::Balanced
                }
            }
            ExecutionMode::Hybrid => ScanProfile::Turbo,
            ExecutionMode::PacketBlast => ScanProfile::Aggressive,
        };
    }
    strategy::apply_runtime_overrides(&mut request, &strategy);
    if let Some(chapter) = request.profile.tbns_chapter() {
        global_warnings.push(format!(
            "tbns active: tri-blue-network-scans chapter={} profile={} safety-bus engaged for low-impact discovery",
            chapter,
            request.profile.as_str()
        ));
    }
    global_warnings.extend(strategy.notes.iter().cloned());
    if request.rate_limit_pps != Some(strategy.rate_limit_pps) {
        global_warnings.push(format!(
            "custom rate override active: {} pps",
            request.rate_limit_pps.unwrap_or(strategy.rate_limit_pps)
        ));
    }
    if request.max_retries != Some(strategy.max_retries) {
        global_warnings.push(format!(
            "custom retry override active: {}",
            request.max_retries.unwrap_or(strategy.max_retries)
        ));
    }

    let defer_host_enrichment = shard_dimension == "ports";
    let mut host_queue = VecDeque::from(work_items);
    let bundle_plan = scan_bundle::plan(
        request.profile,
        request.service_detection,
        request.strict_safety,
    );
    let mut snapshot_writer = if request.session_id.is_some() {
        Some(config::open_host_snapshot_writer()?)
    } else {
        None
    };
    global_warnings.push(format!(
        "scan bundle selected: {} [{}]",
        bundle_plan.name, bundle_plan.summary
    ));
    let host_concurrency =
        host_parallelism(&request, &strategy, selected_ports.len(), host_queue.len());
    let mut in_flight = FuturesUnordered::new();
    let mut hosts = Vec::new();
    let mut async_tasks = 0usize;
    let mut parallel_tasks = 0usize;
    let mut lua_hooks_ran = false;

    while in_flight.len() < host_concurrency {
        if stop_signal::should_stop() {
            break;
        }
        let Some(work_item) = host_queue.pop_front() else {
            break;
        };
        in_flight.push(process_host(
            request.clone(),
            work_item,
            global_warnings.clone(),
            service_registry.clone(),
            fingerprint_db.clone(),
            strategy.clone(),
            defer_host_enrichment,
        ));
    }

    while let Some(result) = in_flight.next().await {
        if stop_signal::should_stop() {
            break;
        }
        let execution = result?;
        async_tasks += execution.async_tasks;
        thread_pool_tasks += execution.thread_pool_tasks;
        parallel_tasks += execution.parallel_tasks;
        lua_hooks_ran = lua_hooks_ran || execution.lua_hooks_ran;
        let checkpoint_unit = execution.checkpoint_unit.clone();
        if let (Some(session_id), Some(writer)) =
            (request.session_id.as_deref(), snapshot_writer.as_mut())
        {
            writer.save(
                session_id,
                &execution.host,
                if defer_host_enrichment {
                    "partial"
                } else {
                    "final"
                },
            )?;
        }
        hosts.push(execution.host);
        if let Some(runtime) = checkpoint_runtime.as_mut() {
            if runtime.completed_units.insert(checkpoint_unit) {
                persist_shard_checkpoint_state(
                    &request,
                    total_shards,
                    shard_index,
                    shard_dimension,
                    selected_ports.len(),
                    runtime,
                )?;
            }
        }

        if let Some(work_item) = host_queue.pop_front() {
            if stop_signal::should_stop() {
                break;
            }
            in_flight.push(process_host(
                request.clone(),
                work_item,
                global_warnings.clone(),
                service_registry.clone(),
                fingerprint_db.clone(),
                strategy.clone(),
                defer_host_enrichment,
            ));
        }
    }

    if defer_host_enrichment {
        hosts = merge_hosts_by_ip(hosts);
        for host in &mut hosts {
            if stop_signal::should_stop() {
                break;
            }
            let (extra_thread_pool_tasks, extra_parallel_tasks, extra_lua_hooks_ran) =
                finalize_host(&request, host).await?;
            thread_pool_tasks += extra_thread_pool_tasks;
            parallel_tasks += extra_parallel_tasks;
            lua_hooks_ran = lua_hooks_ran || extra_lua_hooks_ran;
            if let (Some(session_id), Some(writer)) =
                (request.session_id.as_deref(), snapshot_writer.as_mut())
            {
                writer.save(session_id, host, "final")?;
            }
        }
    }

    let checkpoint_enabled = checkpoint_runtime.is_some();
    let mut checkpoint_unit_label = "none".to_string();
    let mut checkpoint_planned_units = 0usize;
    let mut checkpoint_completed_units = 0usize;
    let mut checkpoint_resumed_units = 0usize;
    if let Some(runtime) = checkpoint_runtime.as_ref() {
        checkpoint_unit_label = runtime.unit_label.clone();
        checkpoint_planned_units = runtime.planned_units.len();
        checkpoint_completed_units = runtime.completed_units.len();
        checkpoint_resumed_units = runtime.resumed_units;
    }
    if let Some(runtime) = checkpoint_runtime.take() {
        if runtime.completed_units.len() >= runtime.planned_units.len() {
            config::clear_shard_checkpoint(&runtime.signature)?;
        } else {
            persist_shard_checkpoint_state(
                &request,
                total_shards,
                shard_index,
                shard_dimension,
                selected_ports.len(),
                &runtime,
            )?;
        }
    }

    let finished = Utc::now();
    let fp_stats = fingerprint_db.stats();
    let platform = capability_registry::summary();
    let profiled_hosts = hosts
        .iter()
        .filter(|host| host.device_class.is_some())
        .count();
    let fragile_hosts = hosts
        .iter()
        .filter(|host| {
            matches!(
                host.device_class.as_deref(),
                Some("fragile-embedded") | Some("printer-sensitive")
            )
        })
        .count();
    let safety_ports_suppressed = hosts
        .iter()
        .flat_map(|host| host.ports.iter())
        .filter(|port| port.matched_by.as_deref() == Some("device-profile-safety"))
        .count();
    let scan_family = request.profile.scan_family().to_string();
    let safety_model = if request.profile.is_low_impact_concept() {
        "tbns-safety-bus".to_string()
    } else {
        "defensive-guardrails".to_string()
    };
    let safety_envelope_active = request.lab_mode
        || request.strict_safety
        || has_public_targets
        || public_target_policy_applied
        || fragile_hosts > 0;
    let report = ScanReport {
        metadata: ScanMetadata {
            session_id: request.session_id.clone(),
            started_at: started,
            finished_at: finished,
            duration_ms: (finished - started).num_milliseconds(),
            engine_stats: EngineStats {
                async_engine_tasks: async_tasks,
                thread_pool_tasks,
                parallel_tasks,
                lua_hooks_ran,
                integrity_checked: std::env::var("NPROBE_RS_INTEGRITY_STATE").is_ok(),
                integrity_state: std::env::var("NPROBE_RS_INTEGRITY_STATE")
                    .unwrap_or_else(|_| "unknown".to_string()),
                integrity_manifest: std::env::var("NPROBE_RS_INTEGRITY_BASELINE")
                    .unwrap_or_else(|_| "unverified".to_string()),
                resource_policy: strategy.resource_policy.clone(),
                scan_bundle: bundle_plan.name,
                scan_bundle_stages: bundle_plan.stages,
                framework_role: "defensive-learning-platform".to_string(),
                scan_family,
                safety_model,
                teaching_mode: request.explain || request.verbose,
                execution_mode: strategy.mode.as_str().to_string(),
                scan_persona: strategy.persona.as_str().to_string(),
                configured_rate_pps: request.rate_limit_pps.unwrap_or(strategy.rate_limit_pps),
                configured_burst_size: request.burst_size.unwrap_or(strategy.burst_size),
                max_retries: request.max_retries.unwrap_or(strategy.max_retries),
                host_parallelism: host_concurrency,
                total_shards,
                shard_index,
                shard_dimension: shard_dimension.to_string(),
                scan_seed: request.scan_seed,
                checkpoint_enabled,
                checkpoint_unit_label,
                checkpoint_planned_units,
                checkpoint_completed_units,
                checkpoint_resumed_units,
                safety_envelope_active,
                public_target_policy_applied,
                profiled_hosts,
                fragile_hosts,
                safety_ports_suppressed,
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
            platform,
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
            arp_discovery: request.arp_discovery,
            report_format: request.report_format,
            lab_mode: request.lab_mode,
            total_shards: request.total_shards,
            shard_index: request.shard_index,
            scan_seed: request.scan_seed,
            resume_from_checkpoint: request.resume_from_checkpoint,
            fresh_scan: request.fresh_scan,
        },
        hosts,
    };

    reporting::run(
        &report,
        request.report_format,
        request.output_path.as_deref(),
    )
    .await?;
    Ok(report)
}

async fn resolve_targets(
    request: &ScanRequest,
    warnings: &mut Vec<String>,
) -> NProbeResult<Vec<IpAddr>> {
    if let Some(cidr) = packet_arp::parse_ipv4_cidr(&request.target) {
        let (fallback_hosts, truncated) = cidr.expand_hosts(MAX_CIDR_HOSTS);
        if fallback_hosts.is_empty() {
            return Err(NProbeError::Parse(format!(
                "cidr target '{}' resolved to zero hosts",
                request.target
            )));
        }
        if truncated {
            warnings.push(format!(
                "cidr target {} exceeds {} hosts; limiting scan scope",
                request.target, MAX_CIDR_HOSTS
            ));
        }

        if request.arp_discovery {
            if !packet_arp::is_lan_ipv4(cidr.network()) {
                warnings.push(
                    "arp sweep skipped: target cidr is not private/link-local ipv4".to_string(),
                );
            } else {
                let sweep = tokio::task::spawn_blocking(move || {
                    packet_arp::sweep_ipv4_cidr(cidr, Duration::from_millis(220), MAX_CIDR_HOSTS)
                })
                .await
                .map_err(NProbeError::Join)?
                .map_err(NProbeError::Io)?;

                warnings.push(format!(
                    "arp sweep: {} responsive hosts from {} probed addresses (cidr host budget={})",
                    sweep.discovered_hosts.len(),
                    sweep.attempted_hosts,
                    sweep.requested_hosts
                ));
                if sweep.truncated {
                    warnings.push(format!(
                        "arp sweep truncated host list to {} addresses",
                        sweep.attempted_hosts
                    ));
                }

                if !sweep.discovered_hosts.is_empty() {
                    return Ok(sweep
                        .discovered_hosts
                        .into_iter()
                        .map(IpAddr::V4)
                        .collect::<Vec<_>>());
                }

                warnings.push(
                    "arp sweep found no live neighbors; falling back to expanded cidr target list"
                        .to_string(),
                );
            }
        }

        return Ok(fallback_hosts
            .into_iter()
            .map(IpAddr::V4)
            .collect::<Vec<_>>());
    }

    dns::resolve(&request.target).await
}

async fn process_host(
    request: ScanRequest,
    work_item: ScanWorkItem,
    global_warnings: Vec<String>,
    service_registry: Arc<ServiceRegistry>,
    fingerprint_db: Arc<FingerprintDatabase>,
    strategy: ScanStrategy,
    defer_enrichment: bool,
) -> NProbeResult<HostExecution> {
    let ip = work_item.ip;
    let engine_result: NProbeResult<(HostResult, usize)> =
        if matches!(strategy.mode, ExecutionMode::PacketBlast) && !request.include_udp {
            match packet_port_scan::run(
                &request,
                ip,
                work_item.ports.clone(),
                service_registry.clone(),
                fingerprint_db.clone(),
                &strategy,
            )
            .await
            {
                Ok(value) => Ok(value),
                Err(raw_err) => {
                    let (mut fallback_host, fallback_tasks) = async_port_scan::run(
                        &request,
                        ip,
                        work_item.ports,
                        service_registry,
                        fingerprint_db,
                        &strategy,
                    )
                    .await?;
                    fallback_host.warnings.push(format!(
                        "packet-blast raw backend unavailable, fallback to async engine: {raw_err}"
                    ));
                    Ok((fallback_host, fallback_tasks))
                }
            }
        } else {
            async_port_scan::run(
                &request,
                ip,
                work_item.ports,
                service_registry,
                fingerprint_db,
                &strategy,
            )
            .await
        };
    let (mut host, async_tasks) = match engine_result {
        Ok(result) => result,
        Err(err) => {
            let host = degraded_host_result(
                &request.target,
                ip,
                &global_warnings,
                &format!(
                    "host scan engine failed for this target, but NProbe-RS kept the session running: {}",
                    err.friendly_detail()
                ),
            );
            return Ok(HostExecution {
                checkpoint_unit: work_item.checkpoint_unit,
                host,
                async_tasks: 0,
                thread_pool_tasks: 0,
                parallel_tasks: 0,
                lua_hooks_ran: false,
            });
        }
    };
    host.warnings.extend(global_warnings);

    let mut thread_pool_tasks = 0usize;
    let mut parallel_tasks = 0usize;
    let mut lua_hooks_ran = false;

    if !defer_enrichment {
        if request.reverse_dns {
            if let Some(reverse_dns) = dns::reverse(ip).await {
                host.reverse_dns = Some(reverse_dns);
                thread_pool_tasks += 1;
            }
        }

        let (analysis_tasks, analysis_warning) = run_analysis_isolated(&mut host, request.explain);
        parallel_tasks = analysis_tasks;
        if let Some(warning) = analysis_warning {
            host.warnings.push(warning);
        }
        let fetcher_report = run_fetchers_isolated(&request, &host).await;
        parallel_tasks += fetcher_report.parallel_tasks;
        host.warnings.extend(fetcher_report.warnings);
        host.insights.extend(fetcher_report.insights);
        host.learning_notes.extend(fetcher_report.learning_notes);
        dedupe_sort_strings(&mut host.warnings);
        dedupe_sort_strings(&mut host.insights);
        dedupe_sort_strings(&mut host.learning_notes);
        let (lua_findings, lua_ok, lua_warning) =
            run_lua_isolated(&host, request.lua_script.as_deref());
        host.lua_findings = lua_findings;
        if let Some(warning) = lua_warning {
            host.warnings.push(warning);
            dedupe_sort_strings(&mut host.warnings);
        }
        if !host.lua_findings.is_empty() {
            host.insights.push(format!(
                "lua hooks added {} custom findings",
                host.lua_findings.len()
            ));
        }
        lua_hooks_ran = lua_ok;
    }

    Ok(HostExecution {
        checkpoint_unit: work_item.checkpoint_unit,
        host,
        async_tasks,
        thread_pool_tasks,
        parallel_tasks,
        lua_hooks_ran,
    })
}

fn degraded_host_result(
    target: &str,
    ip: IpAddr,
    global_warnings: &[String],
    failure_warning: &str,
) -> HostResult {
    let mut warnings = global_warnings.to_vec();
    warnings.push(failure_warning.to_string());
    warnings.push(
        "This host result is partial. Core session execution continued so other hosts could still be scanned."
            .to_string(),
    );
    dedupe_sort_strings(&mut warnings);

    HostResult {
        target: target.to_string(),
        ip: ip.to_string(),
        reverse_dns: None,
        observed_mac: None,
        device_class: None,
        device_vendor: None,
        phantom_device_check: None,
        safety_actions: vec!["fault-isolation:host-scan-degraded".to_string()],
        warnings,
        ports: Vec::new(),
        risk_score: 0,
        insights: vec![
            "host scan incomplete: one engine failed for this target, so NProbe-RS preserved the rest of the session instead of aborting everything".to_string(),
        ],
        defensive_advice: vec![
            "Retry this host after checking permissions, network reachability, and optional engine inputs.".to_string(),
        ],
        learning_notes: vec![
            "Learning: NProbe-RS isolates host-level engine failures so one bad path does not collapse the full run."
                .to_string(),
        ],
        lua_findings: Vec::new(),
    }
}

fn merge_hosts_by_ip(hosts: Vec<HostResult>) -> Vec<HostResult> {
    let mut merged = Vec::<HostResult>::new();
    let mut index_by_ip = BTreeMap::<String, usize>::new();

    for mut host in hosts {
        if let Some(existing_idx) = index_by_ip.get(&host.ip).copied() {
            let existing = &mut merged[existing_idx];
            existing.ports.append(&mut host.ports);
            existing.safety_actions.append(&mut host.safety_actions);
            existing.warnings.append(&mut host.warnings);
            existing.insights.append(&mut host.insights);
            existing.defensive_advice.append(&mut host.defensive_advice);
            existing.learning_notes.append(&mut host.learning_notes);
            existing.lua_findings.append(&mut host.lua_findings);
            if existing.reverse_dns.is_none() {
                existing.reverse_dns = host.reverse_dns.take();
            }
            if existing.observed_mac.is_none() {
                existing.observed_mac = host.observed_mac.take();
            }
            if existing.device_class.is_none() {
                existing.device_class = host.device_class.take();
            }
            if existing.device_vendor.is_none() {
                existing.device_vendor = host.device_vendor.take();
            }
            existing.merge_phantom_device_check(host.phantom_device_check.take());
        } else {
            index_by_ip.insert(host.ip.clone(), merged.len());
            merged.push(host);
        }
    }

    for host in &mut merged {
        host.ports.sort_by(|a, b| {
            a.port
                .cmp(&b.port)
                .then_with(|| a.protocol.cmp(&b.protocol))
        });
        host.ports
            .dedup_by(|left, right| left.port == right.port && left.protocol == right.protocol);
        dedupe_sort_strings(&mut host.safety_actions);
        dedupe_sort_strings(&mut host.warnings);
        dedupe_sort_strings(&mut host.insights);
        dedupe_sort_strings(&mut host.defensive_advice);
        dedupe_sort_strings(&mut host.learning_notes);
        dedupe_sort_strings(&mut host.lua_findings);
    }

    merged
}

fn dedupe_sort_strings(values: &mut Vec<String>) {
    values.sort_unstable();
    values.dedup();
}

async fn finalize_host(
    request: &ScanRequest,
    host: &mut HostResult,
) -> NProbeResult<(usize, usize, bool)> {
    let mut thread_pool_tasks = 0usize;
    if request.reverse_dns {
        if let Ok(ip) = host.ip.parse::<IpAddr>() {
            if let Some(reverse_dns) = dns::reverse(ip).await {
                host.reverse_dns = Some(reverse_dns);
                thread_pool_tasks += 1;
            }
        }
    }

    host.risk_score = 0;
    host.insights.clear();
    host.defensive_advice.clear();
    host.learning_notes.clear();
    host.lua_findings.clear();

    let (analysis_tasks, analysis_warning) = run_analysis_isolated(host, request.explain);
    let mut parallel_tasks = analysis_tasks;
    if let Some(warning) = analysis_warning {
        host.warnings.push(warning);
    }
    let fetcher_report = run_fetchers_isolated(request, host).await;
    parallel_tasks += fetcher_report.parallel_tasks;
    host.warnings.extend(fetcher_report.warnings);
    host.insights.extend(fetcher_report.insights);
    host.learning_notes.extend(fetcher_report.learning_notes);
    dedupe_sort_strings(&mut host.warnings);
    dedupe_sort_strings(&mut host.insights);
    dedupe_sort_strings(&mut host.learning_notes);

    let (lua_findings, lua_ok, lua_warning) = run_lua_isolated(host, request.lua_script.as_deref());
    host.lua_findings = lua_findings;
    if let Some(warning) = lua_warning {
        host.warnings.push(warning);
        dedupe_sort_strings(&mut host.warnings);
    }
    if !host.lua_findings.is_empty() {
        host.insights.push(format!(
            "lua hooks added {} custom findings",
            host.lua_findings.len()
        ));
    }

    Ok((thread_pool_tasks, parallel_tasks, lua_ok))
}

fn run_analysis_isolated(host: &mut HostResult, explain_mode: bool) -> (usize, Option<String>) {
    let mut working_host = host.clone();
    match catch_unwind(AssertUnwindSafe(|| {
        analysis::run(&mut working_host, explain_mode)
    })) {
        Ok(tasks) => {
            *host = working_host;
            (tasks, None)
        }
        Err(_) => (
            0,
            Some(
                "analysis engine had an internal problem for this host, so advanced scoring and explanations were skipped while the scan kept going."
                    .to_string(),
            ),
        ),
    }
}

async fn run_fetchers_isolated(request: &ScanRequest, host: &HostResult) -> FetcherReport {
    let request = request.clone();
    let host = host.clone();
    match tokio::spawn(async move { fetchers::run(&request, &host).await }).await {
        Ok(report) => report,
        Err(_) => FetcherReport {
            warnings: vec![
                "fetcher engine had an internal problem for this host, so optional enrichment was skipped while the scan kept going."
                    .to_string(),
            ],
            insights: Vec::new(),
            learning_notes: vec![
                "Learning: enrichment is optional in NProbe-RS. If a fetcher fails, the core scan result remains usable."
                    .to_string(),
            ],
            parallel_tasks: 0,
        },
    }
}

fn run_lua_isolated(
    host: &HostResult,
    script_path: Option<&Path>,
) -> (Vec<String>, bool, Option<String>) {
    match catch_unwind(AssertUnwindSafe(|| lua::run(host, script_path))) {
        Ok(Ok(findings)) => (findings, true, None),
        Ok(Err(err)) => (
            Vec::new(),
            false,
            Some(format!(
                "lua engine was skipped for this host: {} The scan continued with the core findings.",
                err.friendly_detail()
            )),
        ),
        Err(_) => (
            Vec::new(),
            false,
            Some(
                "lua engine crashed for this host, so NProbe-RS disabled it for this run and kept the scan going."
                    .to_string(),
            ),
        ),
    }
}

fn enforce_safety(
    request: &mut ScanRequest,
    resolved_ips: &[IpAddr],
    warnings: &mut Vec<String>,
) -> NProbeResult<()> {
    let has_public_targets = resolved_ips.iter().any(|ip| !is_private_or_local(ip));
    if request.lab_mode && has_public_targets {
        return Err(NProbeError::Safety(
            "lab mode allows only private/local target addresses".to_string(),
        ));
    }

    if has_public_targets {
        warnings.push(
            "external target detected: ensure documented authorization before scanning".to_string(),
        );

        if !request.allow_external {
            return Err(NProbeError::Safety(
                "public target detected: pass --allow-external (alias: --force-internet) to continue"
                    .to_string(),
            ));
        }

        apply_conservative_limits(request);
        warnings.push(
            "public-target safety envelope active: conservative concurrency, delay, and timeout caps applied"
                .to_string(),
        );
    }

    if request.lab_mode {
        warnings.push("lab mode active: scan constrained to private/local targets".to_string());
    }

    Ok(())
}

fn enforce_defensive_scope(
    request: &mut ScanRequest,
    resolved_ips: &[IpAddr],
    warnings: &mut Vec<String>,
) -> NProbeResult<()> {
    let has_public_targets = resolved_ips.iter().any(|ip| !is_private_or_local(ip));
    let concept_profile = request.profile.is_low_impact_concept();
    let profile_name = format!("{:?}", request.profile).to_ascii_lowercase();

    if has_public_targets && resolved_ips.len() > MAX_PUBLIC_HOSTS {
        return Err(NProbeError::Safety(format!(
            "defensive guard blocked a public-target scan across {} hosts; narrow scope to {} hosts or fewer",
            resolved_ips.len(),
            MAX_PUBLIC_HOSTS
        )));
    }

    if has_public_targets && request.total_shards.unwrap_or(1) > 1 {
        return Err(NProbeError::Safety(
            "defensive guard blocks distributed public-target scans; remove sharding and narrow the scope"
                .to_string(),
        ));
    }

    if concept_profile && !request.strict_safety {
        request.strict_safety = true;
        warnings.push(format!(
            "{profile_name} profile automatically enabled strict-safety for minimal-impact execution"
        ));
    }

    if request.strict_safety && request.profile != ScanProfile::Stealth && !concept_profile {
        warnings.push(format!(
            "strict-safety active: forcing profile {} -> stealth",
            format!("{:?}", request.profile).to_ascii_lowercase()
        ));
        request.profile = ScanProfile::Stealth;
    }

    if has_public_targets && request.profile != ScanProfile::Stealth && !concept_profile {
        warnings.push(format!(
            "public-target defensive guard: forcing profile {} -> stealth",
            format!("{:?}", request.profile).to_ascii_lowercase()
        ));
        request.profile = ScanProfile::Stealth;
    }

    if concept_profile {
        if request.include_udp {
            request.include_udp = false;
            warnings.push(format!(
                "{profile_name} profile disables UDP probing to keep first-contact behavior low-impact"
            ));
        }

        if request.aggressive_root {
            request.aggressive_root = false;
            warnings.push(format!(
                "{profile_name} profile disabled aggressive-root extensions; raw high-pressure probing is outside this concept"
            ));
        }

        if request.privileged_probes {
            request.privileged_probes = false;
            warnings.push(format!(
                "{profile_name} profile disabled privileged raw probes; the concept stays in user-space defensive paths"
            ));
        }

        if request.service_detection {
            request.service_detection = false;
            warnings.push(format!(
                "{profile_name} profile deferred deeper service fingerprinting until later resilience evidence exists"
            ));
        }
    }

    if request.strict_safety || has_public_targets {
        if request.include_udp {
            request.include_udp = false;
            warnings.push(
                "defensive guard disabled UDP probing to minimize amplification and device stress"
                    .to_string(),
            );
        }

        if request.aggressive_root {
            request.aggressive_root = false;
            warnings.push(
                "defensive guard disabled aggressive-root extensions; high-pressure raw probing is not allowed in safe mode"
                    .to_string(),
            );
        }

        if request.privileged_probes {
            request.privileged_probes = false;
            warnings.push(
                "defensive guard disabled privileged raw probes; scan will remain in low-impact user-space paths"
                    .to_string(),
            );
        }
    }

    if request.strict_safety {
        if request.service_detection {
            request.service_detection = false;
            warnings.push(
                "strict-safety active: deeper service fingerprinting deferred unless host evidence later proves resilience"
                    .to_string(),
            );
        }
        apply_safe_mode_limits(request);
    }

    if has_public_targets {
        if request.service_detection {
            request.service_detection = false;
            warnings.push(
                "public-target defensive guard: service detection downgraded to port-state discovery only"
                    .to_string(),
            );
        }
        apply_public_defensive_limits(request);
    }

    if concept_profile {
        apply_low_impact_concept_limits(request, warnings);
    }

    Ok(())
}

fn enforce_privileged_modes(
    request: &mut ScanRequest,
    warnings: &mut Vec<String>,
) -> NProbeResult<()> {
    if !request.requires_root() {
        return Ok(());
    }

    if !has_root_privileges() {
        return Err(NProbeError::Safety(build_root_required_message(request)));
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

fn apply_public_defensive_limits(request: &mut ScanRequest) {
    let defaults = request.profile.defaults();
    let base_concurrency = request.concurrency.unwrap_or(defaults.concurrency);
    let base_delay = request.delay_ms.unwrap_or(defaults.delay_ms);
    let base_timeout = request.timeout_ms.unwrap_or(defaults.timeout_ms);
    let base_rate_pps = request.rate_limit_pps.unwrap_or(1_500);
    let base_burst = request.burst_size.unwrap_or(24);

    request.concurrency = Some(base_concurrency.min(24));
    request.delay_ms = Some(base_delay.max(25));
    request.timeout_ms = Some(base_timeout.max(1800));
    request.rate_limit_pps = Some(base_rate_pps.min(750));
    request.burst_size = Some(base_burst.min(16));
    request.max_retries = Some(request.max_retries.unwrap_or(1).min(1));
}

fn apply_safe_mode_limits(request: &mut ScanRequest) {
    let defaults = request.profile.defaults();
    let base_concurrency = request.concurrency.unwrap_or(defaults.concurrency);
    let base_delay = request.delay_ms.unwrap_or(defaults.delay_ms);
    let base_timeout = request.timeout_ms.unwrap_or(defaults.timeout_ms);
    let base_rate_pps = request.rate_limit_pps.unwrap_or(1_500);
    let base_burst = request.burst_size.unwrap_or(32);

    request.concurrency = Some(base_concurrency.min(32));
    request.delay_ms = Some(base_delay.max(15));
    request.timeout_ms = Some(base_timeout.max(1600));
    request.rate_limit_pps = Some(base_rate_pps.min(1_200));
    request.burst_size = Some(base_burst.min(24));
    request.max_retries = Some(request.max_retries.unwrap_or(2).max(2));
}

fn apply_low_impact_concept_limits(request: &mut ScanRequest, warnings: &mut Vec<String>) {
    let Some(port_budget) = request.profile.concept_port_budget() else {
        return;
    };

    let (max_concurrency, min_delay, min_timeout, max_rate_pps, max_burst, max_retries) =
        match request.profile {
            ScanProfile::Phantom => (4usize, 120u64, 2_600u64, 96u32, 1usize, 1u8),
            ScanProfile::Sar => (6usize, 80u64, 2_400u64, 144u32, 2usize, 1u8),
            ScanProfile::Kis => (4usize, 150u64, 3_200u64, 72u32, 1usize, 1u8),
            _ => return,
        };

    let defaults = request.profile.defaults();
    let base_concurrency = request.concurrency.unwrap_or(defaults.concurrency);
    let base_delay = request.delay_ms.unwrap_or(defaults.delay_ms);
    let base_timeout = request.timeout_ms.unwrap_or(defaults.timeout_ms);
    let base_rate_pps = request.rate_limit_pps.unwrap_or(max_rate_pps);
    let base_burst = request.burst_size.unwrap_or(max_burst);
    let base_retries = request.max_retries.unwrap_or(max_retries);

    request.concurrency = Some(base_concurrency.min(max_concurrency));
    request.delay_ms = Some(base_delay.max(min_delay));
    request.timeout_ms = Some(base_timeout.max(min_timeout));
    request.rate_limit_pps = Some(base_rate_pps.min(max_rate_pps));
    request.burst_size = Some(base_burst.min(max_burst));
    request.max_retries = Some(base_retries.min(max_retries));

    warnings.push(format!(
        "{} profile active: low-impact budget enforced (ports<= {}, concurrency<= {}, delay>= {}ms, timeout>= {}ms, rate<= {}pps, burst<= {}, retries<= {})",
        format!("{:?}", request.profile).to_ascii_lowercase(),
        port_budget,
        max_concurrency,
        min_delay,
        min_timeout,
        max_rate_pps,
        max_burst,
        max_retries
    ));
}

fn apply_defensive_port_policy(
    request: &ScanRequest,
    has_public_targets: bool,
    selected_ports: &mut Vec<u16>,
    warnings: &mut Vec<String>,
) -> NProbeResult<()> {
    if request.strict_safety || has_public_targets {
        let protected_ports = selected_ports
            .iter()
            .copied()
            .filter(|port| UNIVERSAL_PROTECTED_PORTS.contains(port))
            .collect::<Vec<_>>();
        if !protected_ports.is_empty() {
            selected_ports.retain(|port| !UNIVERSAL_PROTECTED_PORTS.contains(port));
            warnings.push(format!(
                "defensive guard skipped protected ports {:?} to avoid device side effects",
                protected_ports
            ));
        }
    }

    let max_ports = if has_public_targets {
        MAX_PUBLIC_PORTS
    } else if request.strict_safety {
        MAX_DEFENSIVE_PORTS
    } else {
        usize::MAX
    };
    if selected_ports.len() > max_ports {
        let previous = selected_ports.len();
        selected_ports.truncate(max_ports);
        warnings.push(format!(
            "defensive guard reduced active port scope from {} to {} ports",
            previous, max_ports
        ));
    }

    if let Some(profile_budget) = request.profile.concept_port_budget() {
        if selected_ports.len() > profile_budget {
            let previous = selected_ports.len();
            selected_ports.truncate(profile_budget);
            warnings.push(format!(
                "{} profile reduced active port scope from {} to {} ports",
                format!("{:?}", request.profile).to_ascii_lowercase(),
                previous,
                profile_budget
            ));
        }
    }

    if selected_ports.is_empty() {
        return Err(NProbeError::Safety(
            "defensive guard left zero safe ports to scan; narrow your selection or disable protected ports from the request"
                .to_string(),
        ));
    }

    Ok(())
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

fn apply_sharding(
    host_targets: Vec<IpAddr>,
    selected_ports: Vec<u16>,
    request: &ScanRequest,
    warnings: &mut Vec<String>,
) -> NProbeResult<ShardingSelection> {
    let Some(total) = request.total_shards else {
        return Ok((host_targets, selected_ports, "none", 1, 0));
    };
    let index = request.shard_index.unwrap_or(0);

    let mut hosts = host_targets;
    let mut ports = selected_ports;
    let dimension = if hosts.len() > 1 {
        hosts = shard_slice(hosts, total, index);
        "hosts"
    } else if ports.len() > 1 {
        ports = shard_slice(ports, total, index);
        "ports"
    } else {
        "none"
    };

    warnings.push(format!(
        "sharding active: index={} total={} dimension={}",
        index, total, dimension
    ));

    if hosts.is_empty() {
        return Err(NProbeError::Parse(format!(
            "shard {} of {} has no hosts to scan",
            index, total
        )));
    }
    if ports.is_empty() {
        return Err(NProbeError::Parse(format!(
            "shard {} of {} has no ports to scan",
            index, total
        )));
    }

    Ok((hosts, ports, dimension, total, index))
}

fn prepare_shard_checkpoint(
    request: &ScanRequest,
    host_targets: Vec<IpAddr>,
    selected_ports: &[u16],
    total_shards: u16,
    shard_index: u16,
    shard_dimension: &str,
    warnings: &mut Vec<String>,
) -> NProbeResult<(Vec<ScanWorkItem>, Option<ShardCheckpointRuntime>)> {
    let work_items = build_scan_work_items(&host_targets, selected_ports, shard_dimension);
    if total_shards <= 1 || shard_dimension == "none" || work_items.is_empty() {
        return Ok((work_items, None));
    }

    let unit_label = if shard_dimension == "ports" {
        "port-batches"
    } else {
        "hosts"
    };
    let planned_units: Vec<String> = work_items
        .iter()
        .map(|item| item.checkpoint_unit.clone())
        .collect();
    let planned_set: HashSet<String> = planned_units.iter().cloned().collect();
    let signature = checkpoint_signature(
        request,
        &planned_units,
        selected_ports,
        total_shards,
        shard_index,
        shard_dimension,
    );

    if request.fresh_scan {
        let _ = config::clear_shard_checkpoint(&signature);
        warnings.push(format!(
            "fresh-scan active: reset checkpoint for shard {}/{}",
            shard_index + 1,
            total_shards
        ));
    }

    let mut completed_units = HashSet::new();
    if request.resume_from_checkpoint && !request.fresh_scan {
        if let Some(existing) = config::load_shard_checkpoint(&signature)? {
            for unit in existing.completed_units {
                if planned_set.contains(&unit) {
                    completed_units.insert(unit);
                }
            }
        }
    }

    let mut resumed_units = completed_units.len();
    if resumed_units >= planned_units.len() && !planned_units.is_empty() {
        warnings.push(format!(
            "completed shard checkpoint found for shard {}/{}; reset and scanning again",
            shard_index + 1,
            total_shards
        ));
        completed_units.clear();
        resumed_units = 0;
        config::clear_shard_checkpoint(&signature)?;
    }

    if resumed_units > 0 {
        warnings.push(format!(
            "resuming shard {}/{} from checkpoint: {} of {} {} already complete",
            shard_index + 1,
            total_shards,
            resumed_units,
            planned_units.len(),
            unit_label
        ));
    } else if !request.resume_from_checkpoint {
        warnings.push(format!(
            "checkpoint resume disabled for shard {}/{}",
            shard_index + 1,
            total_shards
        ));
    }

    let remaining_items = work_items
        .into_iter()
        .filter(|item| !completed_units.contains(&item.checkpoint_unit))
        .collect::<Vec<_>>();

    let runtime = ShardCheckpointRuntime {
        signature,
        unit_label: unit_label.to_string(),
        planned_units,
        completed_units,
        resumed_units,
    };
    persist_shard_checkpoint_state(
        request,
        total_shards,
        shard_index,
        shard_dimension,
        selected_ports.len(),
        &runtime,
    )?;

    Ok((remaining_items, Some(runtime)))
}

fn build_scan_work_items(
    hosts: &[IpAddr],
    selected_ports: &[u16],
    shard_dimension: &str,
) -> Vec<ScanWorkItem> {
    if hosts.is_empty() || selected_ports.is_empty() {
        return Vec::new();
    }

    if shard_dimension == "ports" {
        let mut items = Vec::new();
        for ip in hosts.iter().copied() {
            for (batch_index, chunk) in selected_ports.chunks(PORT_BATCH_SIZE).enumerate() {
                let first = *chunk.first().unwrap_or(&0);
                let last = *chunk.last().unwrap_or(&0);
                let unit = format!("{ip}:ports:{batch_index}:{first}-{last}");
                items.push(ScanWorkItem {
                    checkpoint_unit: unit,
                    ip,
                    ports: chunk.to_vec(),
                });
            }
        }
        return items;
    }

    hosts
        .iter()
        .copied()
        .map(|ip| ScanWorkItem {
            checkpoint_unit: ip.to_string(),
            ip,
            ports: selected_ports.to_vec(),
        })
        .collect()
}

fn checkpoint_signature(
    request: &ScanRequest,
    planned_units: &[String],
    selected_ports: &[u16],
    total_shards: u16,
    shard_index: u16,
    shard_dimension: &str,
) -> String {
    let mut signature_input = String::new();
    signature_input.push_str("nprobe-rs-shard-checkpoint-v1|");
    signature_input.push_str(&request.target);
    signature_input.push('|');
    signature_input.push_str(&format!("{:?}", request.profile));
    signature_input.push('|');
    signature_input.push_str(if request.include_udp { "1" } else { "0" });
    signature_input.push('|');
    signature_input.push_str(if request.service_detection { "1" } else { "0" });
    signature_input.push('|');
    signature_input.push_str(if request.effective_privileged_probes() {
        "1"
    } else {
        "0"
    });
    signature_input.push('|');
    signature_input.push_str(&total_shards.to_string());
    signature_input.push('|');
    signature_input.push_str(&shard_index.to_string());
    signature_input.push('|');
    signature_input.push_str(shard_dimension);
    signature_input.push('|');
    signature_input.push_str(
        &request
            .scan_seed
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_string()),
    );
    signature_input.push('|');
    signature_input.push_str("units=");
    for unit in planned_units {
        signature_input.push_str(unit);
        signature_input.push(',');
    }
    signature_input.push('|');
    signature_input.push_str("ports=");
    for port in selected_ports {
        signature_input.push_str(&port.to_string());
        signature_input.push(',');
    }

    format!("{:016x}", fnv1a64(signature_input.as_bytes()))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = OFFSET_BASIS;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

fn persist_shard_checkpoint_state(
    request: &ScanRequest,
    total_shards: u16,
    shard_index: u16,
    shard_dimension: &str,
    port_count: usize,
    runtime: &ShardCheckpointRuntime,
) -> NProbeResult<()> {
    let mut completed_units: Vec<String> = runtime.completed_units.iter().cloned().collect();
    completed_units.sort_unstable();
    let state = ShardCheckpointState::new(ShardCheckpointArgs {
        signature: runtime.signature.clone(),
        target: request.target.clone(),
        total_shards,
        shard_index,
        shard_dimension: shard_dimension.to_string(),
        unit_kind: runtime.unit_label.clone(),
        planned_units: runtime.planned_units.clone(),
        completed_units,
        port_count,
        scan_seed: request.scan_seed,
    });
    config::save_shard_checkpoint(&state)?;
    Ok(())
}

fn shard_slice<T>(items: Vec<T>, total_shards: u16, shard_index: u16) -> Vec<T> {
    let total = total_shards as usize;
    let index = shard_index as usize;
    items
        .into_iter()
        .enumerate()
        .filter_map(|(idx, item)| {
            if idx % total == index {
                Some(item)
            } else {
                None
            }
        })
        .collect()
}

fn host_parallelism(
    request: &ScanRequest,
    strategy: &ScanStrategy,
    port_count: usize,
    host_count: usize,
) -> usize {
    let cpu_threads = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(4)
        .max(1);
    let base = match request.profile {
        ScanProfile::Stealth => 2,
        ScanProfile::Phantom => 1,
        ScanProfile::Sar => 2,
        ScanProfile::Kis => 1,
        ScanProfile::Balanced => 6,
        ScanProfile::Turbo => 10,
        ScanProfile::Aggressive => 12,
        ScanProfile::RootOnly => 4,
    };
    let mode_floor = match strategy.mode {
        ExecutionMode::Async => 2,
        ExecutionMode::Hybrid => 4,
        ExecutionMode::PacketBlast => 4,
    };
    let per_host_budget = if port_count <= 16 {
        8
    } else if port_count <= 64 {
        16
    } else if port_count <= 256 {
        24
    } else {
        32
    };
    let strategy_cap = (strategy.recommended_concurrency / per_host_budget).max(1);
    let cpu_cap = match strategy.mode {
        ExecutionMode::Async => cpu_threads.saturating_mul(2),
        ExecutionMode::Hybrid => cpu_threads.saturating_mul(3),
        ExecutionMode::PacketBlast => cpu_threads.saturating_mul(3),
    }
    .clamp(2, 48);

    let strict_cap = if request.strict_safety { 8 } else { 48 };

    base.max(mode_floor)
        .min(strategy_cap)
        .min(cpu_cap)
        .min(strict_cap)
        .min(host_count.max(1))
}

#[cfg(test)]
mod tests {
    use super::{
        apply_defensive_port_policy, checkpoint_signature, enforce_defensive_scope, shard_slice,
    };
    use crate::error::NProbeError;
    use crate::models::{ReportFormat, ScanProfile, ScanRequest};
    use std::net::{IpAddr, Ipv4Addr};

    fn base_request() -> ScanRequest {
        ScanRequest {
            target: "127.0.0.1".to_string(),
            session_id: None,
            ports: vec![22, 80, 443],
            top_ports: None,
            include_udp: false,
            reverse_dns: false,
            service_detection: true,
            explain: false,
            verbose: false,
            report_format: ReportFormat::Cli,
            profile: ScanProfile::Balanced,
            profile_explicit: false,
            root_only: false,
            aggressive_root: false,
            privileged_probes: false,
            arp_discovery: false,
            lab_mode: false,
            allow_external: false,
            strict_safety: false,
            output_path: None,
            lua_script: None,
            timeout_ms: None,
            concurrency: None,
            delay_ms: None,
            rate_limit_pps: None,
            burst_size: None,
            max_retries: None,
            total_shards: Some(4),
            shard_index: Some(1),
            scan_seed: Some(99),
            resume_from_checkpoint: true,
            fresh_scan: false,
        }
    }

    #[test]
    fn shard_slice_even_distribution() {
        let values: Vec<u16> = (0..10).collect();
        let shard0 = shard_slice(values.clone(), 3, 0);
        let shard1 = shard_slice(values.clone(), 3, 1);
        let shard2 = shard_slice(values, 3, 2);
        assert_eq!(shard0, vec![0, 3, 6, 9]);
        assert_eq!(shard1, vec![1, 4, 7]);
        assert_eq!(shard2, vec![2, 5, 8]);
    }

    #[test]
    fn checkpoint_signature_changes_with_shard_index() {
        let request = base_request();
        let hosts = vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()];
        let ports = vec![22, 80, 443];

        let sig_a = checkpoint_signature(&request, &hosts, &ports, 4, 1, "hosts");
        let sig_b = checkpoint_signature(&request, &hosts, &ports, 4, 2, "hosts");

        assert_ne!(sig_a, sig_b);
    }

    #[test]
    fn defensive_scope_blocks_broad_public_scans() {
        let mut request = base_request();
        request.allow_external = true;
        let mut warnings = Vec::new();
        let public_targets = (1..=40)
            .map(|octet| IpAddr::V4(Ipv4Addr::new(198, 51, 100, octet)))
            .collect::<Vec<_>>();

        let err = enforce_defensive_scope(&mut request, &public_targets, &mut warnings)
            .expect_err("public scope should be blocked");
        assert!(matches!(err, NProbeError::Safety(_)));
    }

    #[test]
    fn defensive_port_policy_skips_protected_ports_in_safe_mode() {
        let mut request = base_request();
        request.strict_safety = true;
        let mut warnings = Vec::new();
        let mut ports = vec![22, 80, 9100];

        apply_defensive_port_policy(&request, false, &mut ports, &mut warnings)
            .expect("port policy should succeed");
        assert_eq!(ports, vec![22, 80]);
        assert!(!warnings.is_empty());
    }

    #[test]
    fn phantom_profile_forces_minimal_impact_shape() {
        let mut request = base_request();
        request.profile = ScanProfile::Phantom;
        request.include_udp = true;
        request.service_detection = true;
        request.aggressive_root = true;
        request.privileged_probes = true;
        let mut warnings = Vec::new();
        let private_targets = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))];

        enforce_defensive_scope(&mut request, &private_targets, &mut warnings)
            .expect("phantom profile should remain allowed");
        assert!(request.strict_safety);
        assert!(!request.include_udp);
        assert!(!request.service_detection);
        assert!(!request.aggressive_root);
        assert!(!request.privileged_probes);
        assert_eq!(request.concurrency, Some(4));
        assert_eq!(request.burst_size, Some(1));
        assert_eq!(request.max_retries, Some(1));
        assert!(!warnings.is_empty());
    }
}
