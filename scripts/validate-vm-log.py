#!/usr/bin/env python3
"""Validate successful VM markers and real JSON/NDJSON against local schemas.

Requires the development-only jsonschema package; never resolves schemas over
the network. Usage: python scripts/validate-vm-log.py bin/validation-amd64.log
"""
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


def main():
    report_schema = json.loads(Path("docs/report.schema.json").read_text())
    event_schema = json.loads(Path("docs/event.schema.json").read_text())
    for schema in [report_schema, event_schema]:
        Draft202012Validator.check_schema(schema)
    registry = Registry().with_resources([
        (report_schema["$id"], Resource.from_contents(report_schema)),
        (event_schema["$id"], Resource.from_contents(event_schema)),
    ])
    report_validator = Draft202012Validator(report_schema, registry=registry, format_checker=FormatChecker())
    event_validator = Draft202012Validator(event_schema, registry=registry, format_checker=FormatChecker())
    for filename in sys.argv[1:]:
        text = Path(filename).read_text()
        for marker in ["TEST_EXIT=0", "CLI_TEST_EXIT=0", "CLI_EXIT=0", "=== DONE ==="]:
            assert marker in text, (filename, marker)
        assert "--- FAIL:" not in text and "panic:" not in text, filename
        assert "WARNING: DATA RACE" not in text, filename
        for line in text.splitlines():
            if line.startswith("EXTRA_TEST_EXIT="):
                assert line == "EXTRA_TEST_EXIT=0", (filename,line)
        section = text.split("CLI_EXIT=0", 1)[1].split("=== README EXAMPLE ===", 1)[0]
        receipt, _ = json.JSONDecoder().raw_decode(section.lstrip())
        report_validator.validate(receipt)
        assert receipt["summary"]["incomplete"] is False
        assert receipt["summary"]["processes"] == 1
        assert receipt["summary"]["threads"] == 0
        assert receipt["files"] == [], "launch helper leaked into receipt"
        stream = text.split("=== NDJSON SCHEMA SAMPLE ===", 1)[1].split("=== DONE ===", 1)[0]
        records = [json.loads(line) for line in stream.splitlines() if line.startswith("{")]
        assert records and records[-1]["type"] == "report"
        final = records[-1]["report"]
        assert final["summary"]["incomplete"] is False
        assert len(final["executions"]) == 1
        assert final["summary"]["threads"] == 0 and final["files"] == [], "launch helper leaked into NDJSON"
        for record in records:
            event_validator.validate(record)
        print(f"{filename}: kernel tests, CLI tests, report and {len(records)} NDJSON records valid")


if __name__ == "__main__":
    main()
