# hako

hako (箱, "box") runs a command inside an OS-level sandbox.
It exists so you can hand a shell to an AI agent without handing it your SSH keys, your dotfiles, or your network.

The command sees only what the policy allows: filesystem paths on an allowlist, network off unless you say otherwise, and hard resource ceilings.
Everything else fails with a permission error, enforced by the kernel, not by prompt engineering.

On macOS hako compiles the policy to a Seatbelt profile and runs the command through `sandbox-exec`.
On Linux it clones into fresh user, mount, pid, uts, and ipc namespaces (plus a network namespace when offline), builds a minimal root from bind mounts, and pivots into it.
No root, no daemon, no containers to babysit.

## Install

```sh
go install github.com/tamnd/hako@latest
```

## Quickstart

```sh
# run an agent task offline: it can read the system, write only here and /tmp
hako run -- npm test

# open the network for one command
hako run --net -- python fetch.py

# belt and suspenders: tight walls plus hard ceilings
hako run -p restricted --timeout 5m --mem 1024 -- ./agent-task.sh

# poke around inside the box yourself
hako shell

# see exactly what a command would get, without running it
hako check
```

The child's exit code passes through untouched.
A timeout exits 124, a hako failure 125.

## Policy

Policy comes from a built-in preset, a `.hako.toml` file in the working directory, or flags, merged in that order (flags win).

```toml
name = "agent-task"

[fs]
read = ["/"]            # subtrees the command may read
write = [".", "/tmp"]   # subtrees it may also write
deny = ["~/notes"]      # always wins, even over write

[net]
allow = false

[limits]
timeout = "10m"
memory_mb = 2048
cpu_seconds = 600
processes = 256
open_files = 1024
file_size_mb = 512

[env]
pass = ["GO*"]          # extra env vars to let through (globs ok)
set = { CI = "1" }      # forced values
```

Secrets are denied by default even when read allows `/`: `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`, gh and gcloud credentials, keychains, `~/.netrc`, `~/.npmrc` and friends.
Set `no_default_deny = true` under `[fs]` if you really want them visible.

The environment is scrubbed too.
Only PATH, HOME, TERM, locale and a few similar variables cross into the box unless you pass more with `pass` or `--pass-env`.

## Presets

| preset     | filesystem                              | network |
|------------|-----------------------------------------|---------|
| restricted | read cwd and system dirs, write nothing | off     |
| standard   | read / minus secrets, write cwd and tmp | off     |
| net        | same as standard                        | on      |
| dev        | standard plus build caches writable     | on      |

`standard` is the default when no `.hako.toml` is present.

## Limits

Wall-clock timeout is enforced by hako killing the process group.
The rest are rlimits (memory via RLIMIT_AS, cpu seconds, process count, open files, file size), applied inside the sandbox by hako re-execing itself, so the ceiling lands on the child and never on hako.
On macOS RLIMIT_AS is advisory at best; treat the timeout as the real backstop there.

## As a library

```go
import (
    "github.com/tamnd/hako/pkg/policy"
    "github.com/tamnd/hako/pkg/sandbox"
    "github.com/tamnd/hako/pkg/shim"
)

func main() {
    shim.Init() // must be first: hako re-execs itself inside the sandbox

    p, _ := policy.Preset("standard", workdir)
    r, _ := p.Resolve()
    res, err := sandbox.Run(ctx, r, sandbox.Command{
        Argv:   []string{"npm", "test"},
        Dir:    workdir,
        Stdout: os.Stdout,
        Stderr: os.Stderr,
    })
}
```

## What it is not

hako is a damage limiter, not a VM.
The sandboxed process shares your kernel, and kernel bugs exist.
For truly hostile code use a virtual machine; for an agent that mostly needs to be kept from your credentials and from `rm -rf ~`, hako is the right weight.

Platform support is macOS and Linux.
The Linux backend is young: it needs an unprivileged-user-namespace kernel (most distros since 5.10), and loopback inside the offline netns is not wired up yet.

## License

MIT
