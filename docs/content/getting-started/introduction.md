---
title: "Introduction"
description: "The problem hako solves, why it is a damage limiter and not a VM, and how it enforces a policy through the kernel."
weight: 10
---

## The problem

You want to hand a shell to an AI agent. The agent will run `npm test`, edit files, maybe fetch a URL. Most of the time it behaves. The rest of the time it reads `~/.ssh`, uploads a file somewhere, or runs `rm -rf ~` because a prompt went sideways.

Prompt engineering does not fix this. You cannot instruct your way out of a process that can open any file your user can open. What you need is a wall the process cannot argue with.

## What hako is

hako runs the command inside an OS-level sandbox built from a policy. The policy says which paths the command may read, which it may write, whether the network is reachable, and how much memory, cpu, and time it gets. Anything outside the policy fails with a permission error. The enforcement is in the kernel, not in a wrapper the child can talk around.

- On macOS the policy compiles to a Seatbelt profile (SBPL) with `(deny default)`, and the command runs under `sandbox-exec`.
- On Linux the command runs in fresh user, mount, pid, uts, and ipc namespaces (plus a network namespace when offline), on a minimal root assembled from bind mounts, with a seccomp filter over it.

No root, no daemon, no image to build. hako re-execs itself to become the sandboxed child, so the ceilings land on the child and never on hako.

## A damage limiter, not a VM

hako is a damage limiter. It keeps a command you mostly trust, or an agent that mostly behaves, away from your credentials, your wider filesystem, and the network. The sandboxed process shares your kernel, and kernel bugs exist. For truly hostile, kernel-aware code, use a virtual machine. For an agent that mostly needs to be kept from your credentials and from `rm -rf ~`, hako is the right weight.

## What it is not

- Not a VM or a hypervisor. There is no guest kernel between the child and yours.
- Not a container runtime. There is no image, no registry, no daemon.
- Not a defense against a policy you wrote too wide. `read = ["/"]` plus `no_default_deny` plus `--all-env` is a formality, not a sandbox.

For the full threat model, what hako defends against and what it does not, see the [security model](/reference/security/).
