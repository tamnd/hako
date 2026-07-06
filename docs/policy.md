# Policy reference

A policy says what a sandboxed command may touch. It comes from three
places, merged in order, with later sources winning:

1. a built-in preset (or `standard` when nothing else is given),
2. a `.hako.toml` file in the working directory, or one named with `-p`,
3. command-line flags.

Paths and env lists accumulate across sources; scalars (network, each
limit) are overridden by the last source that sets them.

## File format

`.hako.toml` is TOML. Relative paths inside it resolve against the
file's own directory. `~` and `$VAR` expand.

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

## Keys

### `name`

Label for the policy, shown by `hako check`. Defaults to the file name.

### `[fs]`

| key | type | default | meaning |
|-----|------|---------|---------|
| `read` | list of paths | preset-defined | subtrees the command may read (and execute) |
| `write` | list of paths | preset-defined | subtrees it may also write; writing implies reading |
| `deny` | list of paths | empty | subtrees always refused, even if `read` or `write` would allow them |
| `no_default_deny` | bool | `false` | disables the built-in secrets deny list |

Paths are subtrees: allowing `/data` allows everything beneath it.
`deny` always wins over `read` and `write`, so it is the safe way to
carve a hole in a broad allow.

The built-in secrets deny list applies even when `read = ["/"]`, unless
you set `no_default_deny = true`:

```
~/.ssh  ~/.aws  ~/.gnupg  ~/.netrc  ~/.npmrc  ~/.pypirc
~/.docker  ~/.kube  ~/.azure  ~/.config/gh  ~/.config/gcloud
~/.cargo/credentials  ~/.cargo/credentials.toml  ~/Library/Keychains
```

### `[net]`

| key | type | default | meaning |
|-----|------|---------|---------|
| `allow` | bool | `false` | `true` opens the whole network |
| `allow_hosts` | list | empty | mediate: reach only these hosts, through a local proxy |

`allow_hosts` implies network access, but the only thing the sandbox can
reach directly is the proxy on loopback. Each entry is a host (`example.com`,
any port), a host with a port (`api.example.com:443`), or a subdomain
wildcard (`*.example.com`, which matches `a.example.com` but not the apex).
Enforced on macOS; on Linux a run with `allow_hosts` errors out rather
than pretend, because the fresh network namespace cannot see the parent's
proxy yet. Use `allow = true` for full network on Linux.

### `[limits]`

Zero (or unset) means unlimited.

| key | type | meaning |
|-----|------|---------|
| `timeout` | duration string | wall-clock ceiling; the process group is killed at the deadline (exit 124) |
| `memory_mb` | int | memory ceiling; cgroup v2 `memory.max` on Linux, `RLIMIT_AS` on macOS |
| `cpu_seconds` | int | CPU time ceiling (`RLIMIT_CPU`) |
| `processes` | int | max processes (`RLIMIT_NPROC`, plus `pids.max` on Linux) |
| `open_files` | int | max open file descriptors (`RLIMIT_NOFILE`) |
| `file_size_mb` | int | largest file the command may create (`RLIMIT_FSIZE`) |

On Linux memory is enforced by cgroup, not `RLIMIT_AS`: capping virtual
address space breaks the Go runtime and the JVM (and hako's own init
process). A run over the cgroup cap is OOM-killed and exits 137. cgroups
need a delegated, writable subtree; without one the memory cap is skipped
and the timeout remains the backstop.

### `[env]`

By default only a small safe set crosses into the sandbox:
`PATH HOME TMPDIR TERM COLORTERM LANG USER LOGNAME SHELL TZ` and any
`LC_*`.

| key | type | meaning |
|-----|------|---------|
| `pass` | list of globs | extra variable names to let through, e.g. `GO*` |
| `set` | map | forced key/value pairs |
| `all` | bool | pass the entire parent environment (leaks tokens; be sure) |

## Flags

Every key has a flag. Flags win over the file and preset.

| flag | key |
|------|-----|
| `--ro PATH` (repeatable) | `fs.read` |
| `--rw PATH` (repeatable) | `fs.write` |
| `--deny PATH` (repeatable) | `fs.deny` |
| `--net` | `net.allow` |
| `--allow-host HOST` (repeatable) | `net.allow_hosts` |
| `--timeout DUR` | `limits.timeout` |
| `--mem MB` | `limits.memory_mb` |
| `--cpu SEC` | `limits.cpu_seconds` |
| `--procs N` | `limits.processes` |
| `--files N` | `limits.open_files` |
| `--env KEY=VALUE` (repeatable) | `env.set` |
| `--pass-env GLOB` (repeatable) | `env.pass` |
| `--all-env` | `env.all` |
| `--workdir DIR` / `-C` | working directory inside the sandbox |
| `--audit FILE` | append a JSONL record of the run and denials |

## Presets

| preset | filesystem | network |
|--------|------------|---------|
| `restricted` | read cwd and system dirs, write nothing | off |
| `standard` | read `/` minus secrets, write cwd and tmp | off |
| `net` | same as standard | on |
| `dev` | standard plus build caches writable (`~/.cache`, `~/Library/Caches`, `~/go/pkg`) | on |

`standard` is the default when no `.hako.toml` is present. Use
`hako check` to print the effective policy without running anything.
