#!/usr/bin/env python3
"""Exercise the real CLI, output framing, status and diff. Requires sudo."""
import json
import pathlib
import subprocess
import sys
import tempfile


binary = str(pathlib.Path(sys.argv[1]).resolve())


def trace(*args, code=0):
    result = subprocess.run(["sudo", "--", binary, *args], capture_output=True, text=True)
    assert result.returncode == code, (result.returncode, result.stderr)
    return result


result = trace("--output", "json", "--", "/bin/sh", "-c", "echo command-stdout; exit 7", code=7)
receipt = json.loads(result.stdout)
assert receipt["schema_version"] == 1
assert receipt["summary"]["exit_code"] == 7
assert "command-stdout" in result.stderr
result = trace("--output", "ndjson", "--", "/bin/true")
records = [json.loads(line) for line in result.stdout.splitlines()]
assert all(record["schema_version"] == 1 for record in records)
assert records[-1]["type"] == "report"
assert any(record.get("kind") == "exec" for record in records[:-1])
with tempfile.TemporaryDirectory() as directory:
    first = pathlib.Path(directory) / "first.json"
    second = pathlib.Path(directory) / "second.json"
    # JSON reports normally have root-owned mode 0600. Test file mode explicitly,
    # and copy a stdout receipt into user-owned diff fixtures.
    report_file = pathlib.Path(directory) / "private.json"
    trace("--output", str(report_file), "--", "/bin/true")
    mode = subprocess.check_output(["sudo", "stat", "-c", "%a", str(report_file)], text=True).strip()
    assert mode == "600", mode
    trace("--output", str(report_file), "--", "/bin/true", code=125)
    first.write_text(json.dumps(receipt))
    receipt["start"] = "2099-01-01T00:00:00Z"
    receipt["summary"]["duration_ns"] += 1000
    for process in receipt["processes"]:
        process["pid"] += 1000
    second.write_text(json.dumps(receipt))
    same = subprocess.run([binary, "diff", str(first), str(second)], capture_output=True, text=True)
    assert same.returncode == 0 and same.stdout == "", same
    receipt["files"].append({"operation": "write", "path": "/new-effect", "process_id": "1"})
    second.write_text(json.dumps(receipt))
    changed = subprocess.run([binary, "diff", str(first), str(second)], capture_output=True, text=True)
    assert changed.returncode == 1 and "+ WRITE /new-effect" in changed.stdout, changed
    subprocess.run(["sudo", "rm", "--", str(report_file)], check=True)
print("CLI smoke tests passed")
