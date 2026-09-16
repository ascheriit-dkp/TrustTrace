# Testing

## Local checks

```sh
make generate      # clang with the BPF backend
make check         # gofmt, go vet, unit tests
go test -race ./...
make integration   # sudo: real kernel + CLI tests, loopback only
```

Unit tests run without privileges. Kernel tests are opt-in via
`TRUSTTRACE_INTEGRATION=1`; once enabled, failures to load or attach BPF fail
the tests rather than silently skipping them. The GitHub Actions workflow tests
Ubuntu amd64 and arm64. It explicitly reports a skip only when kernel BTF is
unavailable on the runner; other privilege/verifier failures remain failures.

Integration fixtures execute native code and real syscalls. Coverage includes:

- exec, child/grandchild lineage, inherited executable state and task exits;
- success, nonzero exits, signal exits and descendants surviving the root;
- regular file read/create/modify/rename/delete and unrelated-process exclusion;
- directories, hard links, literal symlink targets, `linkat(AT_EMPTY_PATH)`
  source descriptors and relative path bases;
- IPv4/IPv6 loopback connections;
- executable hashing, executable mappings and empty argv elements;
- JSON, NDJSON, private report files, stdout/stderr separation and Ctrl+C;
- real ring-buffer saturation and pending-map exhaustion with counted loss;
- cancellation and argument-truncation diagnostics;
- detection of real i386 syscalls on amd64 (when the kernel supports that ABI).

The fixtures do not need external Internet access. Tests can be run in a
disposable VM when host capabilities, lockdown or virtualization policies
prevent tracing directly.

## Software-emulated VM

`scripts/mkinitramfs.py` builds an in-memory test environment from a static
BusyBox APK, a native Linux binary, and native test binaries. It downloads
nothing. Obtain a kernel with BTF and the matching static BusyBox package from
a trusted distribution, and keep the test tools outside the repository.

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/trusttrace ./cmd/trusttrace
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o bin/collector.test ./internal/collector
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o bin/cli.test ./cmd/trusttrace
python3 scripts/mkinitramfs.py --busybox-apk /path/to/busybox-static.apk \
  --cli-tests bin/cli.test --output bin/initramfs.gz
qemu-system-x86_64 -accel tcg -m 1536 -smp 2 \
  -kernel /path/to/vmlinuz-virt -initrd bin/initramfs.gz \
  -append 'console=ttyS0 quiet panic=-1' -nographic -no-reboot -nic none
```

For arm64, cross-build with `GOARCH=arm64`, use an arm64 kernel/BusyBox and
`qemu-system-aarch64 -machine virt -cpu cortex-a72`, with `console=ttyAMA0`.
No host filesystem, host network, hypervisor privilege, or hardware
virtualization is needed. TCG verification is slower than native CI.

A successful run prints `TEST_EXIT=0`, `CLI_TEST_EXIT=0`, `CLI_EXIT=0`, then
powers down. QEMU's own zero exit code is not a test pass: inspect these markers
and the test output. Serial logs, binaries and initramfs files belong in the
ignored `bin/` directory.

Validate the real receipt and NDJSON records against the local schemas:

```sh
python3 -m pip install jsonschema referencing  # development tools only
python3 scripts/validate-vm-log.py bin/validation-amd64.log bin/validation-arm64.log
```

For race validation, compile the four package test binaries with `go test -c
-race`, pass the collector and CLI binaries as above, and pass the report and
diff binaries with repeated `--extra-test` arguments. Each extra suite must
print `EXTRA_TEST_EXIT=0`; the validator also rejects race reports.
Cross-built race binaries need a C toolchain for the target. The recorded
amd64 VM run used Zig's musl target with static external linking and 2 GiB RAM.

If a TCG guest exhibits host-clock jumps or watchdog stalls, use
`-accel tcg,thread=single -icount shift=auto,sleep=on` to drive its clock from
emulated instructions. This is a test environment, not a performance benchmark.

`make release` also runs `scripts/verify-release.py`: the two named artifacts
must match their SHA-256 checksums, have the expected ELF architectures and
contain no dynamic loader or dynamic-linking segment. See [VALIDATION.md](VALIDATION.md)
for the completed runs and [LEVEL1_REVIEW.md](LEVEL1_REVIEW.md) for specification coverage.
