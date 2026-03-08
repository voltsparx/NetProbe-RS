use std::collections::BTreeSet;

use crate::models::PlatformStats;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CapabilityStatus {
    Implemented,
    Partial,
    Planned,
    IntentionallyExcluded,
}

#[derive(Debug, Clone, Copy)]
struct CapabilityEntry {
    tool_family: &'static str,
    domain: &'static str,
    capability: &'static str,
    status: CapabilityStatus,
    safe_scope: &'static str,
}

const CAPABILITIES: &[CapabilityEntry] = &[
    CapabilityEntry {
        tool_family: "masscan",
        domain: "discovery",
        capability: "high-speed asynchronous TCP discovery",
        status: CapabilityStatus::Partial,
        safe_scope: "bounded by rate governance, authorization checks, and adaptive safety policy",
    },
    CapabilityEntry {
        tool_family: "masscan",
        domain: "transport",
        capability: "separate transmit and receive engine coordination",
        status: CapabilityStatus::Partial,
        safe_scope: "used for defensive discovery and observability workflows",
    },
    CapabilityEntry {
        tool_family: "masscan",
        domain: "governance",
        capability: "adaptive rate control and packet safety envelope",
        status: CapabilityStatus::Implemented,
        safe_scope: "always-on safety guardrails remain enabled",
    },
    CapabilityEntry {
        tool_family: "gpu-hybrid",
        domain: "packet-crafting",
        capability: "GPU-aware hybrid packet staging and workgroup-aligned dispatch planning",
        status: CapabilityStatus::Partial,
        safe_scope: "stays bounded by the same defensive rate, burst, and scope governance as the raw packet path",
    },
    CapabilityEntry {
        tool_family: "gpu-hybrid",
        domain: "visualization",
        capability: "instance-buffer convergence visualizer and live discovery staging",
        status: CapabilityStatus::Planned,
        safe_scope: "planned as an operator-facing observability surface, not an autonomous execution plane",
    },
    CapabilityEntry {
        tool_family: "gpu-hybrid",
        domain: "automation",
        capability: "YAML-like action trigger system for shell, notify, and UI effects",
        status: CapabilityStatus::Partial,
        safe_scope: "triggers are intended for local automation and operator-defined responses only",
    },
    CapabilityEntry {
        tool_family: "nmap",
        domain: "fingerprinting",
        capability: "database-driven service fingerprinting and banner correlation",
        status: CapabilityStatus::Implemented,
        safe_scope: "focused on identification and explanation, not intrusive exploitation",
    },
    CapabilityEntry {
        tool_family: "nmap",
        domain: "os-fingerprinting",
        capability: "passive nmap-os-db loading and evidence-backed host OS/profile hints",
        status: CapabilityStatus::Partial,
        safe_scope:
            "limited to passive correlation from service, CPE, and low-confidence TTL evidence",
    },
    CapabilityEntry {
        tool_family: "nmap",
        domain: "reporting",
        capability: "multi-format output and explainable scan results",
        status: CapabilityStatus::Implemented,
        safe_scope: "teaching-first reporting is part of the default product behavior",
    },
    CapabilityEntry {
        tool_family: "nmap",
        domain: "scripting",
        capability: "sandboxed script hooks and knowledge-driven enrichment",
        status: CapabilityStatus::Partial,
        safe_scope: "Lua operates through restricted APIs only",
    },
    CapabilityEntry {
        tool_family: "ipscan",
        domain: "enrichment",
        capability: "plugin-style fetcher chain for post-discovery enrichment",
        status: CapabilityStatus::Implemented,
        safe_scope: "fetchers are bounded and aimed at defensive context gathering",
    },
    CapabilityEntry {
        tool_family: "ipscan",
        domain: "history",
        capability: "saved result diffing and run comparison",
        status: CapabilityStatus::Planned,
        safe_scope: "intended for operator review and asset drift tracking",
    },
    CapabilityEntry {
        tool_family: "librenms",
        domain: "inventory",
        capability: "SNMP-based inventory and device enrichment",
        status: CapabilityStatus::Partial,
        safe_scope: "limited to standard inventory-style queries and hints",
    },
    CapabilityEntry {
        tool_family: "librenms",
        domain: "topology",
        capability: "network inventory, topology, and device relationship modeling",
        status: CapabilityStatus::Planned,
        safe_scope: "planned for observability and documentation rather than offensive mapping",
    },
    CapabilityEntry {
        tool_family: "nagioscore",
        domain: "health",
        capability: "health-style checks, scheduler integration, and monitoring posture",
        status: CapabilityStatus::Planned,
        safe_scope: "intended for authorized uptime and safety monitoring workflows",
    },
    CapabilityEntry {
        tool_family: "nagioscore",
        domain: "orchestration",
        capability: "task execution boundaries and fault-isolated worker handling",
        status: CapabilityStatus::Partial,
        safe_scope: "engine isolation remains a core architectural requirement",
    },
    CapabilityEntry {
        tool_family: "openvas-scanner",
        domain: "knowledge",
        capability: "feed-oriented policy and finding correlation layer",
        status: CapabilityStatus::Planned,
        safe_scope: "limited to defensive knowledge ingestion and result correlation",
    },
    CapabilityEntry {
        tool_family: "openvas-scanner",
        domain: "api",
        capability: "daemon/API oriented orchestration and scan control plane",
        status: CapabilityStatus::Planned,
        safe_scope: "intended for local orchestration and team-safe automation",
    },
    CapabilityEntry {
        tool_family: "openvas-scanner",
        domain: "vulnerability-testing",
        capability: "intrusive vulnerability test execution and exploit-like checks",
        status: CapabilityStatus::IntentionallyExcluded,
        safe_scope: "excluded from this framework's default scope for safety and abuse prevention",
    },
];

pub fn summary() -> PlatformStats {
    let mut tool_families = BTreeSet::new();
    let mut capability_domains = BTreeSet::new();
    let mut implemented = 0usize;
    let mut partial = 0usize;
    let mut planned = 0usize;
    let mut intentionally_excluded = 0usize;
    let capability_total = CAPABILITIES
        .iter()
        .filter(|entry| !entry.capability.is_empty() && !entry.safe_scope.is_empty())
        .count();

    for entry in CAPABILITIES {
        tool_families.insert(entry.tool_family.to_string());
        capability_domains.insert(entry.domain.to_string());
        match entry.status {
            CapabilityStatus::Implemented => implemented += 1,
            CapabilityStatus::Partial => partial += 1,
            CapabilityStatus::Planned => planned += 1,
            CapabilityStatus::IntentionallyExcluded => intentionally_excluded += 1,
        }
    }

    PlatformStats {
        capability_total,
        implemented,
        partial,
        planned,
        intentionally_excluded,
        tool_families: tool_families.into_iter().collect(),
        capability_domains: capability_domains.into_iter().collect(),
        guardrail_statement: "NProbe-RS tracks parity against enterprise tool families, but retains structural safety boundaries and excludes intrusive exploit-style capability by default."
            .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::summary;

    #[test]
    fn platform_summary_has_expected_tool_families() {
        let stats = summary();
        assert!(stats.tool_families.iter().any(|tool| tool == "masscan"));
        assert!(stats.tool_families.iter().any(|tool| tool == "nmap"));
        assert!(stats.intentionally_excluded >= 1);
    }
}
