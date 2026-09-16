# Level 1 specification review

Scope: the original TrustTrace Level 1 specification, reviewed on 2026-09-16.
Runtime results and their environmental limits are recorded in [VALIDATION.md](VALIDATION.md).

| Requirement | Implementation and verification |
|---|---|
| Run one command and isolate its tree | Two-pipe launch gate; tracked TIDs; real unrelated-process exclusion test |
| Process lifecycle and hierarchy | Fork/clone, exec and exit; opaque task/parent IDs, PID/PPID, argv, UID, times, duration, status; child/grandchild and orphan tests |
| Meaningful filesystem activity | Successful regular-file open/read/create/write/truncate, rename/delete, directories, links and nodes; deduplicated report plus raw events; file, vectored-I/O and link integration tests |
| IPv4 and IPv6 network activity | Process, IP/port, protocol, time and raw connect result; real loopback tests for both families |
| DNS where practical | Explicitly omitted; IP addresses retained; no reverse lookup or invented hostname attribution |
| Executable SHA-256 | Userspace hashing, device/inode checks, metadata-aware cache, explicit errors; real executable, cache invalidation and unresolved-path tests |
| Structured report | One bounded model for command, process tree, executions, files, network, hashes, diagnostics and summary |
| Table / JSON / NDJSON / report file | All requested modes; version 1 schemas; final NDJSON report; structured stdout separation and private-file tests |
| Behavioral diff | Sorted sets of behavior; ignores PIDs/times/order/duplicate effects; hash, argv, link-target and exit differences; internal ignore predicate |
| Diagnostics and loss | Real ring saturation and map exhaustion tests; correlation/path/argv/hash/encoding/retention errors; explicit incomplete receipts |
| Exit and shutdown | Root status preserved; signal and Ctrl+C tests; descendant draining, pidfd signal forwarding and bounded escalation; attachments/maps closed |
| Repository quality | Go formatting/vet/unit/race tests; privileged Linux tests; amd64/arm64 embedded BPF and static binaries; version injection, reproducibility/checksum checks, CI, draft release workflow, required documentation/license |

No missing mandatory Level 1 feature was identified in this review within the
documented native-syscall coverage. This does not claim coverage of every Linux
operation or every kernel/distribution configuration.

## Explicit boundaries

- Optional local network endpoints and reliable DNS attribution are omitted.
- Compatibility ABIs, asynchronous/delegated work, metadata-only filesystem
  changes and other unsupported operations are documented in [LIMITATIONS.md](LIMITATIONS.md).
- Bounded paths/argv and post-exec hashing can produce incomplete receipts.
  These are reported, not replaced with guessed evidence.
- Diff compares effects globally. It does not distinguish which process
  performed an otherwise identical effect or compare child-only exit changes;
  the complete reports retain that evidence.
- Executable mappings already present in the implementation are retained.
  No additional stretch goals were introduced during final validation.

The required security distinction is explicit in the README: observing no
suspicious behavior does not establish that a program is safe.
