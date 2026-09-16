#!/usr/bin/env python3
"""Check release checksums, ELF architectures and static linkage (stdlib only)."""
import hashlib
from pathlib import Path
import struct
import sys


def main():
    directory = Path(sys.argv[1] if len(sys.argv) > 1 else "dist")
    expected = {"trusttrace-linux-amd64": 62, "trusttrace-linux-arm64": 183}
    checksums = {}
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split()
        assert name not in checksums, f"duplicate checksum: {name}"
        checksums[name] = digest
    assert checksums.keys() == expected.keys(), "unexpected release file list"
    for name, machine in expected.items():
        data = (directory / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == checksums[name], name
        assert data[:6] == b"\x7fELF\x02\x01", f"not ELF64 little endian: {name}"
        assert struct.unpack_from("<HH", data, 16) == (2, machine), name
        offset = struct.unpack_from("<Q", data, 32)[0]
        size, count = struct.unpack_from("<HH", data, 54)
        assert size >= 56 and count > 0 and offset + size * count <= len(data), name
        headers = [struct.unpack_from("<I", data, offset + size * i)[0] for i in range(count)]
        assert 3 not in headers and 2 not in headers, f"dynamic loader/linkage: {name}"
        print(f"{name}: checksum, architecture and static ELF verified")


if __name__ == "__main__":
    main()
