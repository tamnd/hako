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

# or open it to named hosts only, everything else refused
hako run --allow-host api.openai.com --allow-host '*.githubusercontent.com' -- ./agent

# record what the run did and every access it was denied
hako run --audit run.jsonl -- ./agent

# let the agent edit a copy-on-write clone, then review the diff
hako run --overlay -- ./agent

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
allow = false                     # true opens the whole network
allow_hosts = ["api.openai.com"]  # or mediate: only these hosts, via a local proxy

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

## Network

Three modes, cheapest first:

- offline (default): no network at all. On Linux the command runs in its own network namespace with only loopback up.
- allowlist (`--allow-host`, `[net] allow_hosts`): the command's traffic is funnelled through a small CONNECT proxy that only dials the hosts you name; the sandbox itself is confined to loopback, so it cannot reach anything else even by IP. Hosts may pin a port (`api.example.com:443`) or match subdomains (`*.example.com`). macOS only for now; on Linux it errors out rather than pretend to enforce.
- open (`--net`): full network, no mediation.

## Limits

Wall-clock timeout is enforced by hako killing the process group.
Memory, cpu seconds, process count, open files, and file size are applied inside the sandbox by hako re-execing itself, so the ceiling lands on the child and never on hako.
Memory is the exception worth knowing: on Linux it is a cgroup v2 `memory.max` (RLIMIT_AS breaks Go and the JVM, so it is avoided), and a run over the cap is OOM-killed; on macOS it is RLIMIT_AS, which is coarse, so treat the timeout as the real backstop there.

## Overlay mode

`--overlay` runs the command against a copy-on-write clone of the working
directory instead of the directory itself. The command writes freely into
the clone; your original tree is never touched. When it finishes, hako
prints what changed and where the clone lives, so you can review the diff
before applying anything.

```
hako run --overlay -- ./agent-that-edits-files
hako: overlay: 3 change(s)
  ~ src/main.go
  + src/new.go
  - old.txt
review the writes at: /tmp/hako-overlay-1234/project
```

On macOS the clone is an APFS `clonefile`, so it is near-instant and uses
no extra disk until a file is written. Elsewhere it is a plain recursive
copy. The command sees the clone as its working directory, so relative
paths land in the clone; absolute paths back to the original are still
governed by the normal policy.

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
The Linux backend needs an unprivileged-user-namespace kernel (most distros since 5.10). On top of namespaces it installs a seccomp filter that blocks ptrace, kexec, bpf, and module loading, and caps memory with cgroup v2 where the session delegates it. The one gap versus macOS is host-allowlist networking, which is not wired for the fresh netns yet.

See [docs/policy.md](docs/policy.md) for every config key and [docs/security.md](docs/security.md) for the threat model and what hako does and does not defend against.

## License

MIT
