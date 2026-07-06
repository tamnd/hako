# Security model

hako is a damage limiter. It keeps a command that you mostly trust, or an
agent that mostly behaves, away from your credentials, your wider
filesystem, and the network. It is not a boundary against determined,
hostile, kernel-aware code. For that, use a VM.

This page states the threat model, then walks the escape hatches we
looked at and where each one stands.

## What it defends against

- Reading files outside the policy's allowlist (SSH keys, cloud creds,
  the rest of your home directory). Secrets are denied even when `read`
  is `/`.
- Writing anywhere but the paths you granted. `rm -rf ~` hits a wall.
- Reaching the network when you did not ask for it, or reaching hosts you
  did not name when you used an allowlist.
- Runaway resource use: wall-clock, memory, cpu, process count, open
  files, file size.
- Leaking your environment. Only a small safe set of variables crosses in.

## What it does not defend against

- Kernel exploits. The sandboxed process shares your kernel; a kernel bug
  is game over. hako narrows the reachable attack surface (seccomp blocks
  the obvious escalation syscalls on Linux) but cannot close it.
- Side channels, timing, and anything that reads without a syscall the
  sandbox mediates.
- A policy you wrote too wide. `read = ["/"]` plus `no_default_deny` plus
  `--all-env` is not a sandbox, it is a formality.

## How enforcement works

- macOS: the policy compiles to a Seatbelt profile (SBPL) with
  `(deny default)`, and the command runs under `sandbox-exec`. SBPL is
  last-match-wins, so denies are emitted after allows and always win. The
  profile generator refuses paths with control characters and is fuzzed
  to prove no path can break out of its string literal to inject a rule.
- Linux: the command runs in fresh user, mount, pid, uts, and ipc
  namespaces (plus a network namespace when offline). The root is a
  tmpfs assembled from read-only and read-write bind mounts, then
  `pivot_root`ed into. A seccomp filter blocks ptrace, kexec, bpf, and
  module loading. Memory is capped with cgroup v2 where the session
  delegates it.

## Escape-hatch review

### Filesystem denies

`deny` is layered over `read`/`write` and always wins. On macOS it is a
trailing `(deny file-read* file-write* (subpath ...))`; on Linux the
denied path is covered with an empty, unreadable mount (a `mode=0000`
tmpfs for directories, an empty file bind for files), so its contents are
gone, not merely unlisted. The default secrets list applies unless you opt
out.

### File descriptor inheritance

Only stdin, stdout, and stderr cross into the child. hako never sets
`ExtraFiles`, so an open fd to a secret in the parent cannot be inherited
past fd 2. If you wire your own stdio to a sensitive file, that is on you.

### /proc and process visibility

On Linux `/proc` is mounted fresh inside the new pid namespace, so the
child sees only the processes in its own sandbox, numbered from 1. It
cannot read `/proc/<host-pid>/environ` or `/proc/<host-pid>/mem` for
anything on the host, because those pids do not exist in its namespace.
`/dev` is a fresh tmpfs holding only null, zero, full, random, urandom,
and tty, so device nodes cannot be used to reach host state. On macOS
there is no pid namespace; process-info is allowed for the runtime's
sake, but the sandbox denies the file and mach operations that would turn
a pid into useful access.

### The shared terminal (TIOCSTI)

When you run hako attached to a terminal, the child shares that
controlling tty. A hostile child can attempt the `TIOCSTI` ioctl to push
characters into the terminal's input queue, which the parent shell would
then read as if you typed them. Modern Linux kernels gate `TIOCSTI`
behind `dev.tty.legacy_tiocsti` (default off), so the attempt fails with
EIO; macOS has no such switch. For untrusted code, do not give it your
terminal: run with stdio wired to pipes or files (as hako does when
embedded as a library, and as `--audit`-driven batch runs do), which
removes the shared tty entirely.

### Nested sandboxes

Running hako inside hako works: Seatbelt profiles nest (the inner profile
can only further restrict), and user namespaces nest as long as the
kernel allows it. A nested run can never widen the outer policy, only
narrow it.

## Reporting

Found a way out that the threat model says should hold? Open an issue with
a reproduction. Escapes that rely on kernel bugs or on an over-wide policy
are known limits, not hako defects.
