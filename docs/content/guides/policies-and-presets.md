---
title: "Policies and presets"
description: "How policy resolves from preset to file to flags, the four built-in presets, writing a .hako.toml, and the default secrets deny list."
weight: 10
---

A policy says what a sandboxed command may touch: filesystem paths, network, resource limits, and environment.

## How policy resolves

Policy comes from three places, merged in order, with later sources winning:

1. a built-in preset (or `standard` when nothing else is given),
2. a `.hako.toml` file in the working directory, or one named with `-p`,
3. command-line flags.

Paths and env lists accumulate across sources. Scalars (the network setting, each limit) are overridden by the last source that sets them. So flags win over the file, and the file wins over the preset.

If you pass `-p` with a name that matches a preset, that preset is the base. If `-p` names a file, that file is loaded. With no `-p`, hako looks for `./.hako.toml`, and falls back to the `standard` preset when there is none.

## The four presets

| preset | filesystem | network |
|--------|------------|---------|
| `restricted` | read cwd and system dirs, write nothing | off |
| `standard` | read `/` minus secrets, write cwd and tmp | off |
| `net` | same as `standard` | on |
| `dev` | `standard` plus build caches writable | on |

The exact grants, from the preset definitions:

- `restricted`: read is the system directories (`/usr`, `/bin`, `/sbin`, `/opt`, `/etc`, `/var`, `/tmp`, `/System`, `/Library`, `/private`, `/lib`, `/lib64`, `/proc`, `/run`) plus the current working directory. No writes. Network off.
- `standard`: read `/`, write the working directory, `/tmp`, and the system temp directory. Network off. This is the default when no `.hako.toml` is present.
- `net`: identical to `standard`, with the network on.
- `dev`: `net` plus write access to build caches, `~/.cache`, `~/Library/Caches`, and `~/go/pkg`.

The secrets deny list applies to every preset, so even `read = ["/"]` does not expose `~/.ssh` and friends. List the presets any time with `hako presets`.

## Writing a .hako.toml

`.hako.toml` is TOML. Relative paths inside it resolve against the file's own directory. `~` and `$VAR` expand. Drop it in your working directory and hako picks it up automatically.

```toml
name = "agent-task"

[fs]
read  = ["/"]            # subtrees the command may read
write = [".", "/tmp"]    # subtrees it may also write
deny  = ["~/notes"]      # always wins, even over write
no_default_deny = false  # keep the built-in secrets deny list

[net]
allow = false                     # true opens the whole network
allow_hosts = ["api.openai.com"]  # or mediate: only these hosts, via a local proxy

[limits]
timeout      = "10m"
memory_mb    = 2048
cpu_seconds  = 600
processes    = 256
open_files   = 1024
file_size_mb = 512

[env]
pass = ["GO*"]          # extra env vars to let through (globs ok)
set  = { CI = "1" }     # forced values
all  = false            # true passes the entire parent env (leaks tokens)
```

Paths are subtrees: allowing `/data` allows everything beneath it. Writing implies reading, so a path in `write` does not also need to be in `read`.

For every key, its type, and its default, see the [policy keys reference](/reference/policy-keys/).

## Overriding on the command line

Every path and limit has a flag. Flags win over the file and preset.

- `--ro PATH` adds a readable subtree (repeatable).
- `--rw PATH` adds a writable subtree (repeatable).
- `--deny PATH` adds a denied subtree, which always wins (repeatable).

```sh
hako run --ro /data --rw ./out --deny ~/secrets -- ./agent
```

`deny` is layered over `read` and `write` and always wins, so it is the safe way to carve a hole in a broad allow.

## The default secrets deny list

Secrets are denied by default even when `read` allows `/`. The built-in list:

```
~/.ssh   ~/.aws   ~/.gnupg   ~/.netrc   ~/.npmrc   ~/.pypirc
~/.docker   ~/.kube   ~/.azure
~/.config/gh   ~/.config/gcloud
~/.cargo/credentials   ~/.cargo/credentials.toml
~/Library/Keychains
```

These are refused even when the read set is the whole filesystem. Set `no_default_deny = true` under `[fs]` (or leave it off, which is the point) only if you truly need them visible. Turning it off drops every entry above at once, so it is rarely what you want for an agent workload.
