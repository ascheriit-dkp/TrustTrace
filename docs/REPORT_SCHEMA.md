# Report schema v1

Machine-readable definition: [report.schema.json](report.schema.json).
Reports are plain UTF-8 JSON with `schema_version: 1`. Times are RFC 3339 UTC;
durations are integer nanoseconds. Consumers should tolerate new optional
fields within a schema version and reject unknown schema versions.

| Field | Meaning |
|---|---|
| `tool_version` | Build version, or `dev` |
| `command` | Requested argv, including arguments beyond kernel capture bounds |
| `start`, `end` | Collection window, including event drain/enrichment |
| `processes` | Task nodes; `id` and `parent_id` reconstruct lineage |
| `executions` | Successful execs with argv, UID, time, actual and requested paths |
| `files` | Deduplicated successful effects with attribution |
| `network` | IPv4/IPv6 connect attempts, including failures |
| `hashes` | Unique executable hash results and failures |
| `diagnostics` | Counted coverage limitations, errors and losses |
| `summary` | Counts, elapsed time, root exit status and incomplete flag |

Tasks include `pid`, `tid`, `ppid`, `uid`, `thread`, start/end, duration, last
executable and argv. `exit_code` is absent if no exit was observed; zero means
observed success. A signal exit is encoded as `128 + signal`, with the signal
number also stored separately. Processes can have multiple execution records.
Forked tasks that never exec still appear in `processes`.

File operations are `read`, `create`, `write`, `rename`, `delete`, and `load`.
`read` includes opening a regular file for reading; it does not assert every
byte was read. `write` requires a positive write result or successful truncation.
`create` uses the kernel-created flag, not the presence of `O_CREAT` alone.
Rename retains both names and flags (including exchange semantics).
Creation `kind` distinguishes regular files, directories, hard links, symlinks,
and nodes. A hard link's `target` is its source path; a symlink's `target` is
the literal link content, which can be relative. Existing reports without a
creation kind are interpreted as regular file creation.
Names are scoped to the observed task's filesystem namespace.
`load` denotes a successful executable file mapping; its `flags` hold the
mmap protection bits. It can identify shared libraries without assuming every
executable mapping is a library. Anonymous/JIT mappings are outside this list.

Network `status` is `connected`, `in_progress`, or `failed`. `result` preserves
the negative errno; EINPROGRESS (-115) does not establish eventual success.
`protocol` is `tcp`, `udp`, `ipproto:N`, or `unknown`. Numeric IPv6 scope IDs
remain explicit. No hostname is inferred from an IP address.

Every hash has a `path` and `source`: `proc_exe`, `proc_root`,
`path_after_exec`, or `unavailable`. A successful record has a lowercase
64-character `sha256`; failures have `error`. Files that change across observed
execs can yield multiple hash records for the same path.

Each diagnostic has a stable `code`, occurrence `count`, human explanation,
and `loss` boolean. Any loss makes `summary.incomplete` true. This flag means
known observation loss; false still does not mean all possible Linux behavior
was observable. Always apply the documented coverage limits.

Summary filesystem counts are unique paths across tasks, including directories
and links. Files written is the union
of created and written paths. Connection counts include repeated attempts and
failures. Process counts exclude thread nodes; `threads` counts those separately.
