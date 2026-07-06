---
title: "Quick start"
description: "A guided first run: offline commands, opening the network, allowlisting hosts, auditing, overlay, shell, and check."
weight: 30
---

This walks you from a plain offline run to the pieces you will actually use. Everything here is `hako run`, `hako shell`, and `hako check`.

## Run something offline

The default policy (`standard`) reads the filesystem minus secrets, writes your working directory and `/tmp`, and has the network off.

```sh
hako run -- npm test
```

Everything after `--` is the command and its arguments. The test suite runs with no way to reach the network and no write access outside here and `/tmp`.

## Open the network

When a command genuinely needs the network, turn it on for that run.

```sh
hako run --net -- python fetch.py
```

## Allowlist hosts instead of opening everything

Rather than the whole internet, name the hosts the command may reach. Everything else is refused, even by IP.

```sh
hako run --allow-host api.openai.com --allow-host '*.githubusercontent.com' -- ./agent
```

The traffic is funnelled through a small CONNECT proxy that only dials the hosts you name. This is macOS only for now. On Linux an allowlist run errors out rather than pretend to enforce it, so use `--net` there. See [networking](/guides/networking/) for the details.

## Record what happened

Append a JSONL record of the run and every denied access to a file.

```sh
hako run --audit run.jsonl -- ./agent
```

Each line is one JSON object. Tail it, grep it, or feed it to `jq`.

## Let the agent edit a copy, then review

`--overlay` runs the command against a copy-on-write clone of the working directory. The command writes freely into the clone, your original tree is never touched, and hako prints what changed when it finishes.

```sh
hako run --overlay -- ./agent-that-edits-files
```

```
hako: overlay: 3 change(s)
  ~ src/main.go
  + src/new.go
  - old.txt
review the writes at: /tmp/hako-overlay-1234/project
```

## Poke around inside the box yourself

`hako shell` opens your shell inside the sandbox with the same policy machinery, so you can see for yourself what a command would and would not be able to do.

```sh
hako shell
```

## See the effective policy without running anything

`hako check` prints the policy that would apply (name, workdir, network, read/write/deny sets, limits) and runs nothing.

```sh
hako check
hako check -p restricted --timeout 5m --mem 1024
```

## Belt and suspenders

Combine tight walls with hard ceilings.

```sh
hako run -p restricted --timeout 5m --mem 1024 -- ./agent-task.sh
```

## Exit codes

The child's exit code passes through untouched. A timeout exits 124. A hako failure (bad policy, sandbox could not start) exits 125.
