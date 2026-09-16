#!/usr/bin/env python3
"""Build a disposable Linux kernel-test initramfs (no host mounts or network).

Inputs are a static BusyBox APK, a Linux trusttrace binary, and collector.test.
This helper never downloads or installs software and needs no third-party libs.
"""
import argparse
import gzip
import io
from pathlib import Path
import stat
import tarfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--busybox-apk", required=True, type=Path)
    parser.add_argument("--binary", type=Path, default=Path("bin/trusttrace"))
    parser.add_argument("--tests", type=Path, default=Path("bin/collector.test"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--run", default=".", help="Go test regex")
    parser.add_argument("--cli-tests", type=Path)
    parser.add_argument("--compat-fixture", type=Path)
    parser.add_argument("--extra-test", type=Path, action="append", default=[])
    args = parser.parse_args()
    archive = io.BytesIO()
    inode = 0

    def add(name, data=b"", mode=stat.S_IFREG | 0o755):
        nonlocal inode
        inode += 1
        name = name.encode() + b"\0"
        values = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0]
        archive.write(b"070701" + "".join(f"{v:08x}" for v in values).encode())
        archive.write(name)
        archive.write(b"\0" * (-archive.tell() % 4))
        archive.write(data)
        archive.write(b"\0" * (-archive.tell() % 4))

    for directory in ["bin", "dev", "proc", "sys", "tmp", "etc"]:
        add(directory, mode=stat.S_IFDIR | 0o755)
    with tarfile.open(args.busybox_apk, "r:gz", ignore_zeros=True) as apk:
        busybox = apk.extractfile("bin/busybox.static").read()
    add("bin/busybox", busybox)
    for name in ["sh", "mount", "mkdir", "ls", "cat", "rm", "ip", "poweroff", "true", "echo"]:
        add("bin/" + name, b"busybox", stat.S_IFLNK | 0o777)
    add("bin/trusttrace", args.binary.read_bytes())
    add("install.sh", Path("testdata/install.sh").read_bytes())
    add("collector.test", args.tests.read_bytes())
    if args.cli_tests:
        add("cli.test", args.cli_tests.read_bytes())
    if args.compat_fixture:
        add("compat32", args.compat_fixture.read_bytes())
    for index, test in enumerate(args.extra_test):
        add(f"extra-test-{index}", test.read_bytes())
    add("init", b"""#!/bin/sh
export PATH=/bin
mount -t devtmpfs devtmpfs /dev
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t tracefs tracefs /sys/kernel/tracing
ip link set lo up
echo '=== RELEASE VERSION ==='
trusttrace --version
echo "VERSION_EXIT=$?"
echo '=== KERNEL CAPABILITIES ==='
ls /sys/kernel/btf/vmlinux
echo '=== REAL KERNEL TESTS ==='
if test -x /compat32; then export TRUSTTRACE_COMPAT_FIXTURE=/compat32; fi
TRUSTTRACE_INTEGRATION=1 /collector.test -test.v -test.timeout=600s -test.run='TEST_PATTERN'
echo "TEST_EXIT=$?"
for suite in /extra-test-*; do
    if test -x "$suite"; then
        "$suite" -test.v -test.timeout=60s
        echo "EXTRA_TEST_EXIT=$?"
    fi
done
if test -x /cli.test; then
    TRUSTTRACE_INTEGRATION=1 /cli.test -test.v -test.timeout=600s
    echo "CLI_TEST_EXIT=$?"
fi
echo '=== CLI SMOKE ==='
trusttrace --output /tmp/run.json -- /bin/true
echo "CLI_EXIT=$?"
cat /tmp/run.json
echo '=== README EXAMPLE ==='
trusttrace -- /install.sh
echo '=== NDJSON SCHEMA SAMPLE ==='
trusttrace --output ndjson -- /bin/true
echo '=== DONE ==='
poweroff -f
""".replace(b"TEST_PATTERN", args.run.encode()))
    add("TRAILER!!!", mode=0)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(gzip.compress(archive.getvalue(), mtime=0))


if __name__ == "__main__":
    main()
