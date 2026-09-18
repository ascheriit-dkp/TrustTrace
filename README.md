# trusttrace

Run a command. See what it actually did.

trusttrace records the processes, filesystem changes and outbound
connections produced by one command and its descendants.

No daemon. No backend. No telemetry.

```sh
sudo trusttrace -- ./install.sh
```

Real output from [the test fixture](testdata/install.sh), installed as
`/install.sh` in an Alpine Linux test VM:

```text
COMMAND
  "/install.sh"

EXECUTED
  /bin/busybox

NETWORK
  (none observed)

FILES WRITTEN
  /tmp/trusttrace-demo

FILES DELETED
  /tmp/trusttrace-demo

SUMMARY
  processes:     2
  files read:    2
  files written: 1
  connections:   0
  duration:      0.40s
  exit code:     0
```

## Build

Targets Linux amd64 or arm64, kernel 5.15+ with BTF and raw syscall tracepoints.
The tested kernel matrix is recorded in [Validation](docs/VALIDATION.md).
Tracing requires root or equivalent BPF/perf privileges. Builds require Go
1.24+ and Make. Clang with a BPF backend is needed to regenerate kernel objects.

```sh
make build
sudo install -m 0755 bin/trusttrace /usr/local/bin/trusttrace
# After changing BPF source:
make generate build
```

Release builds embed the BPF objects and need no compiler at runtime.
Building a release requires Clang's BPF backend and Python 3 as well as Go/Make.
Use `make release VERSION=v0.1.0` to build both architectures, `SHA256SUMS`,
`LICENSE` and `THIRD_PARTY_NOTICES.md` in `dist/`. This command builds locally;
it does not tag or publish a release. Verify with `(cd dist && sha256sum -c SHA256SUMS)`.
Keep both notice files with redistributed binaries. The tag-triggered GitHub
workflow uploads these five assets to a draft release for review.

## Receipts and diff

```sh
sudo trusttrace -- npm install
sudo trusttrace -- make
sudo trusttrace --output json -- ./foo
sudo trusttrace --output ndjson -- ./foo
sudo trusttrace --output report.json -- ./foo
trusttrace diff first.json second.json
```

Table output is the default. JSON and NDJSON reserve stdout for structured
data and send the command's stdout to stderr. A `.json` filename creates a
new private report (0600); existing files are never overwritten. With `sudo`,
that file is owned by root. File output also prints the normal table.

Reports include task lineage, exec argv/UIDs/exits, file effects, executable
file mappings, IP connect results, executable SHA-256 hashes and diagnostics.
NDJSON streams raw normalized events and ends with the full report. Diff
ignores PIDs, times, durations and semantically irrelevant ordering by default.

The CLI returns the root command's exit code, or `128 + signal`. Tracer/output
failures return 125; usage errors return 2. Known observation loss marks the
receipt `incomplete` and is printed to stderr. Descendants are traced until
they exit, even if the original command exits first. Ctrl+C requests shutdown.

## Limits

This is not a sandbox or malware scanner. **“No suspicious behavior observed”
does not mean “this program is safe.”** `sudo` also gives the command root
privileges. Use a disposable VM for untrusted code.

DNS attribution, unconnected UDP, asynchronous I/O and some filesystem
operations are not covered. Paths and argv are bounded. Hashes are checked
after exec, not signed attestations of the bytes executed. Read
[LIMITATIONS.md](docs/LIMITATIONS.md) before interpreting a receipt.

## Development

```sh
make check          # formatting, go vet, unit tests
make integration    # privileged real-kernel and CLI tests
go test -race ./...
```

Validated on Linux 6.12.31 for amd64 and arm64: full kernel/CLI regressions,
including directory and link events, pass. Linux amd64 race tests, schema checks,
static analysis and reproducible release-build checks pass. The example above
matches captured output. See [validation results](docs/VALIDATION.md) and the
[Level 1 review](docs/LEVEL1_REVIEW.md) for evidence and compatibility limits.

[Architecture](docs/ARCHITECTURE.md) · [Report schema](docs/REPORT_SCHEMA.md) ·
[NDJSON schema](docs/EVENT_SCHEMA.md) · [Diff](docs/DIFF.md) ·
[Testing](docs/TESTING.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md)
