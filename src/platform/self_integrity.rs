use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config;
use crate::error::{NProbeError, NProbeResult};

include!(concat!(env!("OUT_DIR"), "/integrity_manifest.rs"));

const INTEGRITY_STATE_VERSION: u8 = 1;
const INTEGRITY_STATE_FILE: &str = "integrity-state.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityStateRecord {
    pub version: u8,
    pub manifest_sha256: String,
    pub executable_sha256: String,
    pub executable_path: String,
    pub first_trusted_at: String,
    pub last_checked_at: String,
    pub files_checked: usize,
}

#[derive(Debug, Clone)]
pub struct IntegrityStatus {
    pub state: String,
    pub manifest_sha256: String,
    pub executable_sha256: String,
    pub files_checked: usize,
    pub source_tree_verified: bool,
    pub baseline_present: bool,
    pub executable_path: String,
    pub notes: Vec<String>,
}

pub fn enforce_startup() -> NProbeResult<IntegrityStatus> {
    let verification = verify_current_runtime()?;
    let state_path = integrity_state_path()?;
    let mut notes = verification.notes;

    let current_record = IntegrityStateRecord {
        version: INTEGRITY_STATE_VERSION,
        manifest_sha256: BUILD_MANIFEST_SHA256.to_string(),
        executable_sha256: verification.executable_sha256.clone(),
        executable_path: verification.executable_path.clone(),
        first_trusted_at: Utc::now().to_rfc3339(),
        last_checked_at: Utc::now().to_rfc3339(),
        files_checked: verification.files_checked,
    };

    if let Some(mut existing) = load_state_record(&state_path)? {
        if existing.manifest_sha256 != BUILD_MANIFEST_SHA256 {
            return Err(NProbeError::Safety(format!(
                "self-integrity blocked startup: trusted build manifest {} does not match current build {}. Inspect the upgrade and run `nprobe-rs integrity --reseal` to trust it.",
                short_hash(&existing.manifest_sha256),
                short_hash(BUILD_MANIFEST_SHA256)
            )));
        }
        if existing.executable_sha256 != verification.executable_sha256 {
            return Err(NProbeError::Safety(format!(
                "self-integrity blocked startup: executable hash changed from trusted baseline {} to {}. Run `nprobe-rs integrity --reseal` only after verifying the binary is legitimate.",
                short_hash(&existing.executable_sha256),
                short_hash(&verification.executable_sha256)
            )));
        }

        existing.last_checked_at = Utc::now().to_rfc3339();
        existing.files_checked = verification.files_checked;
        existing.executable_path = verification.executable_path.clone();
        save_state_record(&state_path, &existing)?;
        notes.push("integrity baseline matched trusted executable state".to_string());

        return Ok(IntegrityStatus {
            state: "trusted".to_string(),
            manifest_sha256: BUILD_MANIFEST_SHA256.to_string(),
            executable_sha256: verification.executable_sha256,
            files_checked: verification.files_checked,
            source_tree_verified: true,
            baseline_present: true,
            executable_path: verification.executable_path,
            notes,
        });
    }

    save_state_record(&state_path, &current_record)?;
    notes.push(
        "integrity baseline sealed on first trusted startup; future binary or manifest drift will fail closed"
            .to_string(),
    );

    Ok(IntegrityStatus {
        state: "sealed".to_string(),
        manifest_sha256: BUILD_MANIFEST_SHA256.to_string(),
        executable_sha256: verification.executable_sha256,
        files_checked: verification.files_checked,
        source_tree_verified: true,
        baseline_present: false,
        executable_path: verification.executable_path,
        notes,
    })
}

pub fn reseal_trusted_baseline() -> NProbeResult<IntegrityStatus> {
    let verification = verify_current_runtime()?;
    let state_path = integrity_state_path()?;
    let now = Utc::now().to_rfc3339();
    let record = IntegrityStateRecord {
        version: INTEGRITY_STATE_VERSION,
        manifest_sha256: BUILD_MANIFEST_SHA256.to_string(),
        executable_sha256: verification.executable_sha256.clone(),
        executable_path: verification.executable_path.clone(),
        first_trusted_at: now.clone(),
        last_checked_at: now,
        files_checked: verification.files_checked,
    };
    save_state_record(&state_path, &record)?;

    let mut notes = verification.notes;
    notes.push(
        "trusted integrity baseline resealed for the current build and executable".to_string(),
    );

    Ok(IntegrityStatus {
        state: "resealed".to_string(),
        manifest_sha256: BUILD_MANIFEST_SHA256.to_string(),
        executable_sha256: verification.executable_sha256,
        files_checked: verification.files_checked,
        source_tree_verified: true,
        baseline_present: true,
        executable_path: verification.executable_path,
        notes,
    })
}

pub fn status() -> NProbeResult<IntegrityStatus> {
    let verification = verify_current_runtime()?;
    let state_path = integrity_state_path()?;
    let mut notes = verification.notes;
    let existing = load_state_record(&state_path)?;

    let (state, baseline_present) = if let Some(record) = existing {
        if record.manifest_sha256 == BUILD_MANIFEST_SHA256
            && record.executable_sha256 == verification.executable_sha256
        {
            notes.push("stored baseline matches current executable and build manifest".to_string());
            ("trusted".to_string(), true)
        } else {
            notes.push("stored baseline differs from current runtime; reseal is required after manual verification".to_string());
            ("drifted".to_string(), true)
        }
    } else {
        notes.push("no trusted integrity baseline exists yet".to_string());
        ("unsealed".to_string(), false)
    };

    Ok(IntegrityStatus {
        state,
        manifest_sha256: BUILD_MANIFEST_SHA256.to_string(),
        executable_sha256: verification.executable_sha256,
        files_checked: verification.files_checked,
        source_tree_verified: true,
        baseline_present,
        executable_path: verification.executable_path,
        notes,
    })
}

pub fn publish_runtime_status(status: &IntegrityStatus) {
    std::env::set_var("NPROBE_RS_INTEGRITY_STATE", &status.state);
    std::env::set_var(
        "NPROBE_RS_INTEGRITY_BASELINE",
        short_hash(&status.manifest_sha256),
    );
    std::env::set_var(
        "NPROBE_RS_INTEGRITY_EXECUTABLE",
        short_hash(&status.executable_sha256),
    );
}

#[derive(Debug)]
struct RuntimeVerification {
    executable_sha256: String,
    executable_path: String,
    files_checked: usize,
    notes: Vec<String>,
}

fn verify_current_runtime() -> NProbeResult<RuntimeVerification> {
    let mut notes = Vec::new();
    let manifest_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut files_checked = 0usize;

    for (relative_path, expected_sha256) in SAFETY_CRITICAL_FILES {
        let absolute = manifest_root.join(relative_path);
        let actual_sha256 = hash_file(&absolute)?;
        files_checked += 1;
        if actual_sha256 != *expected_sha256 {
            return Err(NProbeError::Safety(format!(
                "self-integrity blocked startup: safety-critical file '{}' differs from the trusted build manifest",
                absolute.display()
            )));
        }
    }
    notes.push(format!(
        "verified {} safety-critical file hashes against the embedded build manifest",
        files_checked
    ));

    let executable_path = std::env::current_exe()?;
    let executable_sha256 = hash_file(&executable_path)?;
    notes.push(format!(
        "computed executable fingerprint {} for {}",
        short_hash(&executable_sha256),
        executable_path.display()
    ));

    Ok(RuntimeVerification {
        executable_sha256,
        executable_path: executable_path.display().to_string(),
        files_checked,
        notes,
    })
}

fn integrity_state_path() -> NProbeResult<PathBuf> {
    Ok(config::config_dir()?.join(INTEGRITY_STATE_FILE))
}

fn load_state_record(path: &Path) -> NProbeResult<Option<IntegrityStateRecord>> {
    if !path.exists() {
        return Ok(None);
    }

    let body = fs::read_to_string(path)?;
    let parsed = serde_json::from_str::<IntegrityStateRecord>(&body).map_err(|err| {
        NProbeError::Config(format!(
            "failed to parse integrity state '{}': {err}",
            path.display()
        ))
    })?;
    if parsed.version != INTEGRITY_STATE_VERSION {
        return Ok(None);
    }
    Ok(Some(parsed))
}

fn save_state_record(path: &Path, record: &IntegrityStateRecord) -> NProbeResult<()> {
    let parent = path.parent().ok_or_else(|| {
        NProbeError::Config("invalid integrity-state path without parent directory".to_string())
    })?;
    fs::create_dir_all(parent)?;
    let tmp_path = parent.join(format!("{INTEGRITY_STATE_FILE}.tmp"));
    let body = serde_json::to_string_pretty(record)?;
    fs::write(&tmp_path, body)?;
    if path.exists() {
        let _ = fs::remove_file(path);
    }
    fs::rename(&tmp_path, path).map_err(|err| {
        let _ = fs::remove_file(&tmp_path);
        NProbeError::Io(err)
    })?;
    Ok(())
}

fn hash_file(path: &Path) -> NProbeResult<String> {
    let bytes = fs::read(path).map_err(|err| {
        NProbeError::Io(std::io::Error::new(
            err.kind(),
            format!(
                "failed to read '{}' for integrity verification: {err}",
                path.display()
            ),
        ))
    })?;
    Ok(hex(&Sha256::digest(&bytes)))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn short_hash(full: &str) -> String {
    full.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::short_hash;

    #[test]
    fn short_hash_truncates_readably() {
        assert_eq!(short_hash("abcdef1234567890"), "abcdef123456");
    }
}
