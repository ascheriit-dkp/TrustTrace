# Level 1 validation

Validation date: 2026-09-16. This records local execution of the working tree,
not a GitHub Actions run or a published release.

## Environment

- Linux kernel **6.12.31-0-virt**, Alpine 3.22.0, on amd64 and arm64.
- Real kernel BPF verifier, BTF relocation, tracepoint attachment and syscalls
  in disposable QEMU TCG guests; two virtual CPUs, no host mounts or network.
  Network tests use guest loopback.
- Go **1.27.1**; BPF compilation with Zig **0.14.1**'s Clang backend using
  `-O2 -g -Wall -Werror`, separately for each architecture.
- Linux amd64 race tests use Go's race detector with static musl external
  linking. All four packages, including privileged collector and CLI tests,
  execute in the guest. The race guest has 2 GiB RAM.

## Completed checks

| Check | Result |
|---|---|
| amd64 kernel verifier and complete collector regression suite | Pass |
| arm64 kernel verifier and complete collector regression suite | Pass |
| Directory, hard-link, symlink, fd-based `linkat`, relative rename/delete | Pass on both architectures |
| CLI formats, private files, output separation, status and Ctrl+C | Pass on both architectures |
| Linux amd64 race-enabled collector, CLI, report and diff suites | Pass; no race reports |
| arm64 report and diff unit suites | Pass |
| Windows portable unit suites | Pass |
| `gofmt`, `go vet` on Windows and Linux amd64/arm64 | Pass |
| `go mod verify`, `go mod tidy -diff` | Pass; no module changes |
| Workflow YAML and actionlint 1.7.7 | Pass |
| Python helper syntax and repository whitespace checks | Pass |
| Static Linux release builds, both architectures | Pass |
| Same-input repeated builds | Byte-for-byte identical on both architectures |
| Release SHA-256, ELF machine and absence of dynamic linkage | Pass |
| Version injection executed on both Linux architectures | `trusttrace v0.1.0-review (fc38d9b-dirty)` |
| Real JSON and NDJSON against local version 1 schemas | Pass on all three final VM runs |
| README output example | Exact match to captured amd64 fixture output |

The amd64 i386 fixture passes and reports unsupported ABI loss instead of
misdecoding compat syscalls. That architecture-specific test explicitly skips
on arm64. Both kernels exercise actual ring-buffer saturation and pending-map
exhaustion; the final normal runs report 29 ring losses and one map insertion
failure in those deliberately constrained tests.

## Release artifacts

Local review builds are in ignored `dist/`, with `SHA256SUMS`. The version and
commit label deliberately identify an uncommitted review build; they are not
a release tag. The builds use the Makefile's release Go flags: disabled CGO,
`-trimpath`, `-buildvcs=false`, stripped symbols, empty build ID and injected
version/commit. No local user source paths remain in the binaries or BPF objects.

| Artifact | SHA-256 |
|---|---|
| trusttrace-linux-amd64 | `fcd7c53d998810d39e2c6289e82861b341511807997cd3edb1b3fca43c238391` |
| trusttrace-linux-arm64 | `3ff2e79f0988fc7076cc5a9fa6104abc6e38792dbfe9a1b173e54fe2ae1040de` |

The host is Windows: BPF and Go release commands were executed explicitly with
the same flags, using Zig's BPF target. Linux Make/Clang and hosted workflow
execution remain CI checks; workflow configuration was linted locally.
`make release` now verifies architecture, static linkage and checksums itself.

## Fixes and interpretation

The final link regression exposed a missing source for `linkat(AT_EMPTY_PATH)`
on both kernels. Capture now handles the empty source through its descriptor
before ordinary pathname handling. Both complete collector suites and the
race suite were rerun with the corrected objects.

One arm64 TCG run experienced a guest-clock jump and an 806-second watchdog
stall during BPF loading. It was rejected as a failed run. The complete arm64
suite was rerun with instruction-counted guest time and passed without changing
or relaxing the test assertions/timeouts. Timings from these guests are not
performance measurements.

The compatibility target remains Linux 5.15+, but **only 6.12.31 was kernel-tested
in this validation**. Other kernels, distribution lockdown policies, native
hardware timing, arm64 race detection and hosted CI are not claimed as tested.
See [LIMITATIONS.md](LIMITATIONS.md) for collection boundaries and
[LEVEL1_REVIEW.md](LEVEL1_REVIEW.md) for the original specification review.

Logs and build artifacts remain local in ignored `bin/` and `dist/`; no tag,
push or release publication was performed during final validation.

Final logs: `bin/validation-amd64.log`, `bin/validation-arm64-final.log`, and
`bin/validation-race-final.log`. Each contains successful collector, CLI and
smoke-test markers and a completed shutdown. The latter two also contain
successful report/diff suite markers and injected release versions.
Recheck them with:

```sh
python3 scripts/validate-vm-log.py bin/validation-amd64.log \
  bin/validation-arm64-final.log bin/validation-race-final.log
python3 scripts/verify-release.py dist
```
