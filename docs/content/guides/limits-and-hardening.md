---
title: "Limits and hardening"
description: "Resource ceilings, the Linux seccomp filter, environment scrubbing, and the audit log."
weight: 40
---

Walls keep a command out of your files and off the network. Ceilings keep it from burning the machine down while it runs inside them.

## Timeout

The wall-clock timeout is enforced by hako itself, which kills the whole process group at the deadline. A run that hits the timeout exits 124. Because it kills the process group, a command that spawned children does not leave them running.

```sh
hako run --timeout 5m -- ./agent-task.sh
```

The timeout is the one ceiling that is always reliable, so treat it as the real backstop, especially for memory on macOS.

## Memory

```sh
hako run --mem 1024 -- ./agent
```

Memory enforcement differs by platform, and the difference is worth knowing:

- On Linux it is a cgroup v2 `memory.max`, not `RLIMIT_AS`. Capping virtual address space breaks the Go runtime, the JVM, and hako's own init process, so it is avoided. A run over the cgroup cap is OOM-killed and exits 137. cgroups need a delegated, writable subtree. Without one the memory cap is skipped and the timeout remains the backstop.
- On macOS it is `RLIMIT_AS`, which is coarse. Treat the timeout as the real ceiling there.

## The other resource ceilings

CPU time, process count, open files, and file size are applied inside the sandbox. hako re-execs itself with the limits encoded in the first argument, sets them on the process that becomes the child, then execs the target. The ceiling lands on the child and never on hako.

- `--cpu SEC`: CPU time ceiling (`RLIMIT_CPU`).
- `--procs N`: max processes (`RLIMIT_NPROC`, plus `pids.max` on Linux).
- `--files N`: max open file descriptors (`RLIMIT_NOFILE`).
- file size: the largest file the command may create (`RLIMIT_FSIZE`), set with `file_size_mb` in a `.hako.toml`.

Zero, or unset, means unlimited for every limit.

## The Linux seccomp filter

On top of namespaces, the Linux backend installs a seccomp filter that blocks the obvious escalation syscalls: `ptrace`, `kexec`, `bpf`, and kernel module loading. This narrows the reachable attack surface. It does not close it: the child still shares your kernel, and a kernel bug is out of scope for a sandbox this weight. See the [security model](/reference/security/) for where that line sits.

## Environment scrubbing

The environment is scrubbed. By default only a small safe set crosses into the box:

```
PATH  HOME  TMPDIR  TERM  COLORTERM  LANG  USER  LOGNAME  SHELL  TZ
```

plus any `LC_*`. Everything else is dropped, so tokens sitting in your shell environment do not leak into the sandbox.

Let more through when a command needs it:

- `--pass-env GLOB` passes named variables through (`--pass-env 'GO*'`, repeatable). In a file, `[env] pass`.
- `--env KEY=VALUE` forces a value (repeatable). In a file, `[env] set`.
- `--all-env` passes the entire parent environment. This leaks tokens. Be sure. In a file, `[env] all`.

## The audit log

`--audit FILE` appends a JSONL record of the run and every denied access. One JSON object per line, so the log is easy to grep, tail, or feed to `jq`.

```sh
hako run --audit run.jsonl -- ./agent
```

Each line is an event with a `time`, a `kind`, and kind-specific `fields`. A run writes a `run.start` (the argv, working directory, network setting, host allowlist, and the sizes of the read, write, and deny sets) and a `run.end` (the exit code and whether it timed out). Denials are recorded as their own events, for example a refused host as `net.deny`. The file is opened for append, so repeated runs stack up in one log.
