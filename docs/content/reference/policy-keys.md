---
title: "Policy keys"
description: "Every .hako.toml key with its type, default, and meaning, and the flag that maps to each."
weight: 20
---

A policy says what a sandboxed command may touch. It comes from three places, merged in order, with later sources winning: a built-in preset (or `standard` when nothing else is given), a `.hako.toml` file in the working directory (or one named with `-p`), and command-line flags.

Paths and env lists accumulate across sources. Scalars (the network setting, each limit) are overridden by the last source that sets them.

## File format

`.hako.toml` is TOML. Relative paths inside it resolve against the file's own directory. `~` and `$VAR` expand.

```toml
name = "agent-task"

[fs]
read  = ["/"]
write = [".", "/tmp"]
deny  = ["~/notes"]
no_default_deny = false

[net]
allow = false
allow_hosts = ["api.openai.com", "*.githubusercontent.com"]

[limits]
timeout      = "10m"
memory_mb    = 2048
cpu_seconds  = 600
processes    = 256
open_files   = 1024
file_size_mb = 512

[env]
pass = ["GO*"]
set  = { CI = "1" }
all  = false
```

## name

Label for the policy, shown by `hako check`. Defaults to the file name (the base name with its extension stripped).

## [fs]

| key | type | default | meaning |
|-----|------|---------|---------|
| `read` | list of paths | preset-defined | subtrees the command may read (and execute) |
| `write` | list of paths | preset-defined | subtrees it may also write; writing implies reading |
| `deny` | list of paths | empty | subtrees always refused, even if `read` or `write` would allow them |
| `no_default_deny` | bool | `false` | disables the built-in secrets deny list |

Paths are subtrees: allowing `/data` allows everything beneath it. `deny` always wins over `read` and `write`, so it is the safe way to carve a hole in a broad allow. Writing implies reading, so a path in `write` does not also need to be in `read`.

The built-in secrets deny list applies even when `read = ["/"]`, unless you set `no_default_deny = true`:

```
~/.ssh   ~/.aws   ~/.gnupg   ~/.netrc   ~/.npmrc   ~/.pypirc
~/.docker   ~/.kube   ~/.azure
~/.config/gh   ~/.config/gcloud
~/.cargo/credentials   ~/.cargo/credentials.toml
~/Library/Keychains
```

Flags: `--ro` maps to `read`, `--rw` to `write`, `--deny` to `deny`, all repeatable and additive.

## [net]

| key | type | default | meaning |
|-----|------|---------|---------|
| `allow` | bool | `false` | `true` opens the whole network |
| `allow_hosts` | list | empty | mediate: reach only these hosts, through a local proxy |

`allow_hosts` implies network access, but the only thing the sandbox can reach directly is the proxy on loopback. Each entry is a host (`example.com`, any port), a host with a port (`api.example.com:443`), or a subdomain wildcard (`*.example.com`, which matches `a.example.com` but not the apex). Enforced on macOS. On Linux a run with `allow_hosts` errors out rather than pretend, because the fresh network namespace cannot see the parent's proxy yet. Use `allow = true` for full network on Linux.

Flags: `--net` maps to `allow`, `--allow-host` to `allow_hosts` (repeatable).

## [limits]

Zero, or unset, means unlimited.

| key | type | meaning |
|-----|------|---------|
| `timeout` | duration string | wall-clock ceiling; the process group is killed at the deadline (exit 124) |
| `memory_mb` | int | memory ceiling; cgroup v2 `memory.max` on Linux, `RLIMIT_AS` on macOS |
| `cpu_seconds` | int | CPU time ceiling (`RLIMIT_CPU`) |
| `processes` | int | max processes (`RLIMIT_NPROC`, plus `pids.max` on Linux) |
| `open_files` | int | max open file descriptors (`RLIMIT_NOFILE`) |
| `file_size_mb` | int | largest file the command may create (`RLIMIT_FSIZE`) |

On Linux memory is enforced by cgroup, not `RLIMIT_AS`: capping virtual address space breaks the Go runtime and the JVM (and hako's own init process). A run over the cgroup cap is OOM-killed and exits 137. cgroups need a delegated, writable subtree; without one the memory cap is skipped and the timeout remains the backstop.

Flags: `--timeout` maps to `timeout`, `--mem` to `memory_mb`, `--cpu` to `cpu_seconds`, `--procs` to `processes`, `--files` to `open_files`. `file_size_mb` has no flag and is set in the file.

## [env]

By default only a small safe set crosses into the sandbox:

```
PATH  HOME  TMPDIR  TERM  COLORTERM  LANG  USER  LOGNAME  SHELL  TZ
```

and any `LC_*`.

| key | type | meaning |
|-----|------|---------|
| `pass` | list of globs | extra variable names to let through, e.g. `GO*` |
| `set` | map | forced key/value pairs |
| `all` | bool | pass the entire parent environment (leaks tokens; be sure) |

Flags: `--pass-env` maps to `pass` (repeatable), `--env KEY=VALUE` to `set` (repeatable), `--all-env` to `all`.

## Presets as a starting point

| preset | filesystem | network |
|--------|------------|---------|
| `restricted` | read cwd and system dirs, write nothing | off |
| `standard` | read `/` minus secrets, write cwd and tmp | off |
| `net` | same as `standard` | on |
| `dev` | `standard` plus build caches writable (`~/.cache`, `~/Library/Caches`, `~/go/pkg`) | on |

`standard` is the default when no `.hako.toml` is present. Use `hako check` to print the effective policy without running anything.
