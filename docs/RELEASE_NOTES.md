# trusttrace v0.1.0 - 2026-09-18

Observe one command and its descendants. Produce a local forensic receipt.

## Included

- Linux amd64/arm64 binaries with embedded CO-RE eBPF objects.
- Process lineage, executions, exit statuses, filesystem effects and connect attempts.
- Executable hashes, explicit loss accounting, JSON/NDJSON and behavioral diffs.

## Requirements

Targets Linux 5.15+ with kernel BTF, BPF syscall support and raw syscall tracepoints.
Root or equivalent BPF/perf privileges. Native 64-bit targets only.
See docs/VALIDATION.md for local and GitHub-hosted test results.

## Known limits

See docs/LIMITATIONS.md before interpreting results. In particular, DNS,
unconnected UDP, asynchronous I/O and precise executable-byte attestation are
not covered. Path and argument capture is bounded. No sandboxing is provided.

## Verification

Assets: `trusttrace-linux-amd64`, `trusttrace-linux-arm64`, `SHA256SUMS`,
`LICENSE` and `THIRD_PARTY_NOTICES.md`. Keep both notice files with redistributed
binaries. `SHA256SUMS` covers both binaries and both notice files.

Download all five assets into one directory and run `sha256sum -c SHA256SUMS`.
Checksums detect accidental
corruption; this release does not provide signed binaries or signed receipts.
