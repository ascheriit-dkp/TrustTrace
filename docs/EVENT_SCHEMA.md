# NDJSON event schema v1

Machine-readable definition: [event.schema.json](event.schema.json).
Each line is one UTF-8 JSON object. Strings are JSON-escaped, so a filename
containing a newline does not split a record. Diagnostics and child stdout go
to stderr in NDJSON mode. Raw events are not retained in memory.

An event has `schema_version: 1`, `type: "event"`, `kind`, a wall-clock `time`,
`monotonic_ns`, opaque `process_id`, optional `parent_id`, host `pid`, `tid`,
`ppid`, `uid`, and numeric `result`. IDs are strings and are scoped to one run.
`thread` marks thread births. Fork's parent ID identifies the spawning task;
follow parent links through thread nodes to obtain process-only ancestry.

| Kind | Additional fields / result |
|---|---|
| `start` | Synthetic root birth before the launch gate opens |
| `fork` | Child identity, parent identity, thread flag |
| `exec` | Kernel executable `path`, requested `path2`, bounded `argv`, `hash` |
| `exit` | Raw Linux wait status in `result` |
| `open` | `path`, `open_flags`, `created`, `regular`; fd or negative errno |
| `read`, `write` | `path`, bytes or negative errno; `truncated` for truncate calls |
| `rename` | Source `path`, destination `path2`, rename flags in `open_flags` |
| `delete` | `path`; zero means success |
| `connect` | `ip`, `port`, `protocol`, optional `scope_id`; syscall result |
| `load` | Executable file mapping: `path`, `protection`, `mapping_flags`; mapped address or negative errno |
| `create` | `path`, `create_kind` (`directory`, `hardlink`, `symlink`, `node`), optional source/target in `path2`; zero means success |
| `unsupported` | Native syscall number in `open_flags`, result |

`flags` is a bit mask: 1 path loss, 2 argv truncation, 4 memory read failure,
8 thread, 16 newly created, 32 regular file, 64 second-path loss. Missing or
failed paths are absent, rather than reconstructed speculatively. Executable
hashes may have `error` instead of `sha256`. An exec's `result` is zero because
it represents committed execution, not a failed attempt.

Wall time is derived from an initial CLOCK_MONOTONIC/wall-clock pair. Kernel
event order is ring-buffer reservation order; consumers must not interpret it
as a total causal ordering of independent CPU activity.

The final line is:

```json
{"schema_version":1,"type":"report","report":{"schema_version":1,"...":"full report"}}
```

The abbreviated object above illustrates the envelope, not a valid complete
report. Validate the contained report against [report.schema.json](report.schema.json).
An interrupted stream without this final record has no final loss accounting.
Never infer completeness from the number of raw records alone.
