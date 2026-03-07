use std::env;
use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

const SAFETY_CRITICAL_FILES: &[&str] = &[
    "Cargo.toml",
    "src/main.rs",
    "src/cli.rs",
    "src/config.rs",
    "src/error.rs",
    "src/models.rs",
    "src/core/orchestrator.rs",
    "src/engine_async/port_scan.rs",
    "src/engine_packet/port_scan.rs",
    "src/engine_intel/device_profile.rs",
    "src/engine_intel/strategy.rs",
    "src/reporter/learning.rs",
];

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("missing CARGO_MANIFEST_DIR");
    let out_dir = env::var("OUT_DIR").expect("missing OUT_DIR");
    let manifest_root = Path::new(&manifest_dir);

    let mut aggregate = Sha256::new();
    let mut file_entries = Vec::new();

    for relative in SAFETY_CRITICAL_FILES {
        println!("cargo:rerun-if-changed={relative}");
        let path = manifest_root.join(relative);
        let bytes = fs::read(&path).unwrap_or_else(|err| {
            panic!(
                "failed to read safety-critical file {}: {err}",
                path.display()
            )
        });
        let file_hash = hex(&Sha256::digest(&bytes));
        aggregate.update(relative.as_bytes());
        aggregate.update([0]);
        aggregate.update(file_hash.as_bytes());
        aggregate.update([0xff]);
        file_entries.push((relative.to_string(), file_hash));
    }

    let build_manifest_sha256 = hex(&aggregate.finalize());
    let generated = format!(
        "pub const BUILD_MANIFEST_SHA256: &str = \"{build_manifest_sha256}\";\n\
         pub const SAFETY_CRITICAL_FILES: &[(&str, &str)] = &[\n{}\n];\n",
        file_entries
            .iter()
            .map(|(path, hash)| format!("    (\"{path}\", \"{hash}\"),"))
            .collect::<Vec<_>>()
            .join("\n")
    );

    fs::write(Path::new(&out_dir).join("integrity_manifest.rs"), generated)
        .expect("failed to write integrity manifest");
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
