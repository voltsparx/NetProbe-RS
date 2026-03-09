# Release Checklist

Use this checklist before publishing NProbe-RS or cutting a tagged release.

## Scope Review

- Confirm the README matches the currently supported live feature set.
- Confirm `nprobe-rs --scan-type` reflects implemented versus cataloged scan concepts accurately.
- Confirm examples use authorized internal or lab targets.

## Build Verification

Run the full local quality gate:

```bash
cargo fmt --all -- --check
cargo check --all-targets
cargo test --all-targets
cargo build --release --bins
```

Optional install smoke check:

```bash
cargo install --path .
nprobe-rs --help
nprs --help
nprobe-rs --scan-type
nprs --scan-type
```

## Packaging Review

- Bump `version` in `Cargo.toml` if this is a new release.
- Review `Cargo.toml` metadata, license, and README for accuracy.
- Review generated artifacts under `target/release/`.
- Confirm both first-class binaries exist under `target/release/`: `nprobe-rs` and `nprs` (or `.exe` on Windows).
- Confirm platform install scripts under `building-scripts/` still match the current CLI.
- Confirm `.github/workflows/ci.yml` and `.github/workflows/release.yml` still match the current build and packaging layout.

## Safety Review

- Keep the documented usage restricted to authorized internal and lab environments.
- Do not advertise cataloged or blocked concepts as live functionality.
- Keep the safety defaults and guardrails enabled in the published branch.

## Release Steps

1. Commit the release-ready tree.
2. Tag the version you are publishing.
3. Let the tagged GitHub Actions release workflow build platform archives and checksum files.
4. Include the verification commands and supported scope in the release notes.
