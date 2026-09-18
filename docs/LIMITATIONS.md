# Observation limits

trusttrace is an observer, not a sandbox or a proof of safety. Absence of a
record is not proof that an action did not occur. `summary.incomplete: false`
means no known loss within the implemented coverage; it does not claim
complete coverage of every Linux execution mechanism.

## Supported environment

- The compatibility target is Linux 5.15+ with BTF, BPF syscalls, ring buffers, CO-RE-compatible task/file
  types and raw syscall/scheduler tracepoints. Missing capabilities fail before
  launching the command. Distribution lockdown policy may prohibit tracing.
  See [VALIDATION.md](VALIDATION.md) for kernels actually tested; the minimum
  version is not a claim that every distribution configuration has been verified.
- Native amd64 or arm64 programs. Compat 32-bit and x32 ABIs are detected using
  thread ABI flags/syscall markers and their syscall effects are omitted with
  an `unsupported_abi` loss diagnostic. Fork/exec/exit lifecycle may still be
  present. Do not use these incomplete receipts as evidence of their effects.
- Tasks started by the command are in scope. Work delegated to an existing
  daemon, service, kernel worker, or remote system is outside the process tree.
- Root tracing does not drop the command's privileges. `sudo` runs the target
  as root. PID/UID fields use host kernel identities. Paths are scoped to each
  task's root/mount namespace; equal path strings in different namespaces may
  refer to different objects. Namespace changes are not modeled as separate
  filesystem identities.

## Files and binaries

- Native open/openat/openat2/creat, read/pread/readv/preadv/preadv2,
  write/pwrite/writev/pwritev/pwritev2,
  truncate/ftruncate, rename/unlink variants, mkdir/rmdir, link, symlink, mknod
  and their available `*at` variants are collected.
- `read` includes successful open-for-read. Write intent alone is not a write.
  Only regular-file reads and writes are retained; descriptor passing and dup
  need no userspace fd cache because the file is resolved in kernel.
- Paths are bounded to 255 bytes and 32 ancestry/mount steps. Long, inaccessible,
  disconnected, concurrently renamed or otherwise unresolved paths can be
  absent and diagnostic counts increase. A dentry walk is not an atomic
  filesystem snapshot. User pathnames can be changed by another thread while
  a syscall copies them. Symlink-sensitive `..` is preserved on rename/delete.
- Argv is bounded to eight arguments of 63 bytes each. Truncation is explicit.
  Environment variables are not captured. Invalid UTF-8 cannot be represented
  faithfully in JSON; affected paths are omitted, invalid argument slots become
  empty strings, and a loss diagnostic marks this substitution.
- mmap shared writable mappings, io_uring setup, sendfile, splice,
  copy_file_range, sendmsg, and addressed sendto trigger unsupported-operation
  diagnostics on successful calls. Their effects are not reconstructed.
- Metadata-only changes (such as chmod/chown), filesystem ioctls and async I/O are not
  covered. These omissions are coverage limits, not necessarily per-event
  losses. The receipt does not contain file contents or file-content hashes.
- File-backed executable mmap calls produce `load` effects, which include
  normal shared-library executable segments. This is not a complete linker
  inventory: mprotect-based executable transitions, JIT code, anonymous maps,
  dynamic symbol resolution and injected code are not identified. Only exec'd
  binaries are hashed; mapped libraries are paths, not executable-file hashes.

SHA-256 is computed in userspace after observing exec. The opened file must
match the kernel-observed device and inode. Cache reuse additionally checks
size, mtime and ctime; changes while hashing cause failure. `/proc/PID/exe` is
preferred, then the process-root path, then the host path with the same identity.
A quickly exited, unlinked or inaccessible binary may not be hashable. Even
matching identity cannot prove exactly which bytes the CPU executed: files
can change before the read, or inode numbers can be reused. The `source` field
and errors remain in the receipt. Scripts are requested paths; the executing
interpreter is the hashed binary.

## Network

- IPv4/IPv6 `connect` attempts are observed for TCP, connected UDP and other
  IP socket protocols. A connect attempt is not evidence of data transfer.
- EINPROGRESS is recorded without claiming eventual success. Local endpoint,
  packet contents, byte counts, unconnected UDP and final socket state are
  not collected. DNS traffic through an existing resolver daemon is outside
  the traced tree. No DNS attribution or reverse lookup is attempted.
- User sockaddr memory can race with the kernel's own copy. Events describe
  captured syscall input and return values, not packet-level proof.

## Loss and termination

Map insertion failures, ring-buffer saturation, missing exec correlation,
failed memory/path reads, truncated argv, hash failures, report retention
limits and missing task exits are explicitly diagnosed. A missing fork event
can produce partial lineage even if later child events arrive. NDJSON contains
repeated events; a final receipt contains deduplicated effects.

The tracer waits for all tracked descendants, including detached ones. Long-
lived descendants therefore keep it running. Shutdown forwards a signal to
the currently tracked process leaders and escalates after a grace period;
tasks stuck in uninterruptible kernel sleep may outlive that bound. A hard
tracer crash/SIGKILL cannot produce a final receipt or guarantee descendant
cleanup. The root launch helper uses parent-death SIGKILL, but this is not
inherited containment. pidfd signaling pins each opened task; the short
lookup-to-open PID-reuse window is not a security boundary.

Raw command output can contain terminal control sequences. Table report fields
are escaped, but trusttrace does not sanitize the observed command's own output.
