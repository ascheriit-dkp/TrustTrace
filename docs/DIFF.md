# Behavioral diff

```sh
trusttrace diff first.json second.json
trusttrace diff --include-metadata first.json second.json
```

The default compares sets of effects. `+` means present only in the second
report and `-` only in the first. Output is sorted and independent of input
event order. Duplicate effects, PIDs, task IDs, timestamps, durations, tool
versions and connection ordering are ignored.

Compared behavior includes executable paths (`EXEC`), executable file mappings
(`LOAD`), executable hashes
(`HASH`), arguments (`ARGV`), execution UIDs (`UID`), file reads/creates/writes/
deletes/renames, directory creation (`MKDIR`), hard links (`LINK`), symlinks
(`SYMLINK`, including the literal target), node creation (`MKNOD`),
connection destination/protocol/status/result, and the root
exit code/signal. Changed arguments or executable bytes therefore count even
when the executable path is unchanged. File operations are compared globally,
so moving the same operation between processes does not currently change the
diff. Repeated activity counts and child-only exit-status differences are not
compared. Dynamic values inside argv or paths are not automatically ignored.

```text
+ EXEC /tmp/loader
+ WRITE /home/alice/.bashrc
+ CONNECT 192.0.2.7:443 tcp connected result=0
- EXEC /usr/bin/curl
```

With `--include-metadata`, the complete serialized reports also participate as
`METADATA` records. This is intentionally verbose and includes array ordering.

Exit status: 0 for no differences, 1 for differences, 2 for invalid input or an
output error. Diff needs no privileges and works on non-Linux systems too.
Only complete report JSON is accepted as input, not an NDJSON stream. An
incomplete report triggers a stderr warning: absence from it is not evidence
that a behavior did not happen.

The Go diff engine accepts an `Options.Ignore(kind, value)` predicate. CLI
ignore-rule syntax is deliberately deferred until there is a concrete use.
