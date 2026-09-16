# Architecture

One invocation owns one set of unpinned BPF maps, five tracepoint attachments,
one ring-buffer reader and one report builder. No service survives the run.

```text
command + descendants
        |
raw sched fork/exec/exit + raw syscall enter/exit tracepoints
        |
tracked tasks + pending operations + counters -> shared ring buffer
                                                |
                                         Go normalization
                                                |
                                    task correlation + SHA-256
                                                |
                                          report model
                                     /         |        \
                                   table      JSON     NDJSON
                                                |
                                          behavioral diff
```

## Start boundary

The parent loads and attaches BPF before launching a copy of itself as a
small launch helper. The helper acknowledges readiness on one inherited pipe
and blocks on a second. This proves its initial exec tracepoint has completed
before registration; `exec.Cmd.Start` alone does not establish that boundary.
The parent seeds
its TID in the tracking map, creates the report's root task, and releases the
gate. The helper is pinned to its original OS thread and replaces itself with
the requested command using `execve`. An inactive tracking entry suppresses
helper filesystem activity and helper threads before this first target exec.
Failed target lookup/exec still returns the helper's 127/126 status.

The command receives the caller's environment, working directory, credentials
and stdin. It has its own process group, which is made foreground when stdin
is a terminal. The previous foreground group is restored afterward.

## Kernel collection

`sched_process_fork` inserts each descendant TID before the child runs.
Filtering uses membership, never a global UID or command-name filter. Threads
are included because they can fork, exec and perform effects. Each task gets
an opaque monotonic sequence ID; reused PIDs do not reuse IDs. No kernel
pointers leave the kernel.

Exec entry snapshots bounded arguments; `sched_process_exec` commits only
successful execs. The executable file comes from the task's `mm->exe_file`, so
a shebang's interpreter is distinct from its requested script path. Nonleader
exec migrates tracking from the old TID to the post-exec TID. Exit records the
kernel wait status and deletes tracking and pending syscall state.

Syscall entry snapshots inputs; return records the result. A successful open
uses the resulting file descriptor's kernel file, including `FMODE_CREATED`,
to distinguish creation from opening an existing path with `O_CREAT`.
Read/write descriptors are resolved at entry, before close/reuse can race
userspace enrichment. Pipes, sockets and terminals are excluded from file
read/write effects. Failed operations remain in NDJSON but do not become
successful file effects.
Directory and node creation have distinct kinds. Hard links retain the source
path (including fd-based `linkat(AT_EMPTY_PATH)`); symlink targets retain their
literal spelling. Relative creation paths use the same captured cwd/dirfd bases.
File-backed executable mmap calls also produce `load` effects, capturing shared
libraries and other executable mappings without parsing loader internals.

Kernel path snapshots traverse at most 32 dentries/mount transitions and
capture at most 255 bytes relative to the task's filesystem root. Relative
rename/delete arguments include a captured cwd or dirfd base. Userspace joins
those bases without rewriting symlink-sensitive `..` components. Failed or
partial path reconstruction produces a counter and an absent path, never a
plausible invented absolute path. These CO-RE snapshots avoid dependence on
`/proc/PID/fd` being alive by the time an event reaches userspace, at the cost
of explicit capture bounds and kernel BTF requirements.

Network records contain the socket protocol, IP family, destination, IPv6
scope, and connect syscall result. EINPROGRESS is pending, not a confirmed
connection. No reverse DNS lookups are issued.
Compat/x32 syscalls are rejected using the architecture's thread ABI flags and
syscall marker, with a counted diagnostic, instead of decoding their numbers
using the native table.

## Bounds and loss

| Resource | Bound | Exhaustion behavior |
|---|---:|---|
| Tracked tasks | 16,384 | Map-insertion counter; missing subtree is possible |
| Pending syscalls | 8,192 | Map-insertion counter; operation may be missing |
| Shared ring buffer | 8 MiB | Lost-event counter |
| Path capture | 255 bytes / 32 steps | Path-loss counter |
| Argv | 8 arguments / 63 bytes each | Argument-truncation counter |
| Report retention | 100,000 records | Report-limit diagnostic; raw stream continues |
| Hash cache | 16,384 entries | Further hashes are computed without caching |

Hash maps use ordinary bounded maps, not silent LRU eviction. Scratch maps and
diagnostic counters are per CPU. Hashing and formatting are userspace work.
Synchronous enrichment can fall behind: ring loss is measured and disclosed.

## Report and shutdown

The builder owns all retained state on one ingestion goroutine. It deduplicates
file effects by task, operation and path. Raw NDJSON is streamed; its final
line contains the same report used by table/JSON output. Executable hashing
checks device/inode identity, caches matching metadata, and checks for changes
while reading. See the limitations of this evidence in LIMITATIONS.md.

The root's exit alone does not end collection: descendants may outlive it.
Normal completion requires the root wait status and an empty tracking map.
On SIGINT, SIGTERM, SIGHUP or cancellation, the tracer signals tracked process
leaders via pidfds, then escalates to SIGKILL after three seconds. A second
signal escalates immediately. A second grace period bounds shutdown. Links
are detached before draining the ring and reading final counters. Closing the
collection releases all kernel state; nothing is pinned to bpffs.

## Building

The only runtime Go dependencies are [cilium/ebpf](https://github.com/cilium/ebpf)
and `golang.org/x/sys`. BPF objects use minimal CO-RE type views, relocated with
the target kernel's BTF. No generated full `vmlinux.h` or runtime compiler is
required. Syscall IDs are compiled separately for amd64 and arm64.

Reference behavior follows the kernel's
[file mode flags](https://github.com/torvalds/linux/blob/v6.12/include/linux/fs.h)
and cilium's [ring-buffer API](https://pkg.go.dev/github.com/cilium/ebpf/ringbuf).
The project has no dependency on socket-connect-bpf.
