# trusttrace — initial release

Observe one command and its descendants. Produce a local forensic receipt.

## Included

- Linux amd64/arm64 binaries with embedded CO-RE eBPF objects.
- Process lineage, executions, exit statuses, filesystem effects and connect attempts.
- Executable hashes, explicit loss accounting, JSON/NDJSON and behavioral diffs.

## Requirements

Linux 5.15+ with kernel BTF, BPF syscall support and raw syscall tracepoints.
Root or equivalent BPF/perf privileges. Native 64-bit targets only.

## Known limits

See docs/LIMITATIONS.md before interpreting results. In particular, DNS,
unconnected UDP, asynchronous I/O and precise executable-byte attestation are
not covered. Path and argument capture is bounded. No sandboxing is provided.

## Verification

Compare the downloaded binary against SHA256SUMS. Checksums detect accidental
corruption; this release does not provide signed binaries or signed receipts.
