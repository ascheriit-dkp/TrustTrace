# Security

trusttrace observes commands. It does not sandbox them or prevent harm.
Running `sudo trusttrace -- COMMAND` runs COMMAND with the same root privileges.
Use a disposable VM for an untrusted command. A hostile root process can tamper
with the tracer, reports, executable files, kernel state, or other processes.

Receipts contain paths, arguments, UIDs and network endpoints. Arguments may
contain secrets. Keep reports local and inspect them before sharing. Report
files are created exclusively with mode 0600. stdout/NDJSON permissions depend
on the caller's redirection and umask. Child output is not sanitized; report
text escapes control characters in observed paths and arguments.

Kernel maps and buffers have fixed capacity. All kernel objects belong to one
run, are unpinned, and are closed on exit. The tracer does not install a service,
send telemetry, or make its own network requests during collection.

Hashes identify files read after exec with matching device/inode identity.
They are not attestations of all bytes executed. Reports are unsigned and are
not tamper-proof. Missing observations do not establish absence of behavior.

Report vulnerabilities privately using this repository's GitHub private
vulnerability reporting feature when available. Otherwise contact the
maintainer before posting exploitable details publicly. Include the version,
architecture, kernel version, reproduction and relevant diagnostics; redact
secrets from receipts.
