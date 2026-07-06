---
title: "hako"
description: "Run a command inside an OS-level sandbox so an AI agent gets a shell without your SSH keys, dotfiles, or network."
heroTitle: "A little box to run agents in"
heroLead: "hako runs a command inside an OS-level sandbox. Hand a shell to an AI agent without handing it your SSH keys, your dotfiles, or your network."
heroPrimaryURL: "/getting-started/quick-start/"
heroPrimaryText: "Get started"
---

hako (箱, "box") runs a command inside an OS-level sandbox. It exists so you can hand a shell to an AI agent without handing it your SSH keys, your dotfiles, or your network.

The command sees only what the policy allows: filesystem paths on an allowlist, network off unless you say otherwise, and hard resource ceilings. Everything else fails with a permission error, enforced by the kernel, not by prompt engineering.

An agent does not need a smarter prompt to be safe with your machine, it needs a damage limiter. hako is that limiter. On macOS it compiles the policy to a Seatbelt profile and runs the command through `sandbox-exec`. On Linux it clones into fresh user, mount, pid, uts, and ipc namespaces, builds a minimal root from bind mounts, and pivots into it. No root, no daemon, no containers to babysit.

```sh
# run a task offline: read the system, write only here and /tmp
hako run -- npm test

# open the network to named hosts only, everything else refused
hako run --allow-host api.openai.com -- ./agent
```

## What it does

- Confines filesystem access to an allowlist you control, with a default deny on secrets even when reads are wide open.
- Keeps the network off by default. Turn it on fully, or mediate it down to named hosts.
- Applies hard resource ceilings: wall-clock timeout, memory, cpu, process count, open files, file size.
- Scrubs the environment so tokens do not leak into the box.
- Records every run and every denied access to a JSONL audit log on request.
- Runs against a copy-on-write clone of your directory so you can review the diff before applying anything.

## Where to go next

- [Introduction](/getting-started/introduction/): the problem hako solves and how it enforces.
- [Installation](/getting-started/installation/): Homebrew, Linux packages, prebuilt archives, `go install`.
- [Quick start](/getting-started/quick-start/): a guided first run.
- [Policies and presets](/guides/policies-and-presets/): how policy resolves and how to write a `.hako.toml`.
- [Networking](/guides/networking/): offline, allowlist, and open modes.
- [Overlay and sessions](/guides/overlay-and-sessions/): review writes before applying, keep one box warm.
- [Limits and hardening](/guides/limits-and-hardening/): timeouts, memory, seccomp, env scrubbing, audit.
- [CLI reference](/reference/cli/), [policy keys](/reference/policy-keys/), and the [security model](/reference/security/).
