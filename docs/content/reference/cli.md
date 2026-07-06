---
title: "CLI reference"
description: "Every hako command and every flag, organized by command."
weight: 10
---

hako reads a policy, sandboxes a command, and passes the child's exit code through. The child's code is returned untouched, a timeout exits 124, and a hako failure exits 125.

## Policy flags

`run`, `shell`, `check`, and `session start` all take the same policy flags. They are listed once here and referenced by the commands below.

| flag | description |
|------|-------------|
| `-p`, `--policy` | policy file or preset name (default: `./.hako.toml`, else `standard`) |
| `--ro PATH` | allow reading this path (repeatable) |
| `--rw PATH` | allow writing this path (repeatable) |
| `--deny PATH` | deny this path even if otherwise allowed (repeatable) |
| `--net` | allow unrestricted network access |
| `--allow-host HOST` | allow network only to this host, via a local proxy (repeatable; host or `host:port`, `*.domain` ok) |
| `--timeout DUR` | kill the command after this long (e.g. `5m`) |
| `--mem MB` | memory ceiling in MB (cgroup on Linux, `RLIMIT_AS` on macOS) |
| `--cpu SEC` | CPU time ceiling in seconds |
| `--procs N` | max processes |
| `--files N` | max open files |
| `-C`, `--workdir DIR` | working directory inside the sandbox |
| `--env KEY=VALUE` | set `KEY=VALUE` in the child environment (repeatable) |
| `--pass-env GLOB` | pass this env var through (glob ok, repeatable) |
| `--all-env` | pass the entire environment through (leaks tokens, be sure) |
| `--audit FILE` | append a JSONL record of the run and every denied access to this file |
| `--overlay` | run against a copy-on-write clone of the workdir and report the diff, leaving the original untouched |

## hako run

```sh
hako run [flags] -- command [args...]
```

Run a command inside the sandbox. Everything after `--` is the command and its arguments. Takes every policy flag above. The child's exit code passes through.

```sh
hako run -- npm test
hako run -p restricted -- ./agent-task.sh
hako run --net --timeout 5m --mem 1024 -- python fetch.py
```

## hako shell

```sh
hako shell [flags]
```

Open your shell inside the sandbox. It runs `$SHELL` (falling back to `/bin/sh`) under the same policy machinery as `run`. Takes every policy flag above. Takes no positional arguments.

## hako check

```sh
hako check [flags]
```

Print the effective policy without running anything: the policy name, working directory, network state, the read, write, and deny sets, and the limits. Takes every policy flag above, so you can check exactly what a given set of flags would produce. Takes no positional arguments.

| flag | description |
|------|-------------|
| `--profile` | dump the generated Seatbelt profile (darwin only) |

```sh
hako check
hako check -p dev --allow-host api.openai.com
hako check --profile   # macOS: prints the SBPL that would be applied
```

## hako presets

```sh
hako presets
```

List the built-in policy presets with a one-line summary of each. Takes no flags or arguments.

## hako session

Keep one sandbox warm and run many commands through it. A session holds a resolved policy and a single working area. Start it once, then exec as many commands as you like against the same box; each command sees the writes the last one made. With `--overlay` the writes accumulate in a clone you review on stop.

### hako session start

```sh
hako session start [flags]
```

Start a session server. It runs in the foreground. Takes every policy flag above, plus:

| flag | description |
|------|-------------|
| `--socket PATH` | unix socket path for the session (default: `hako-session.sock` in the temp dir) |

### hako session exec

```sh
hako session exec [flags] -- command [args...]
```

Run a command in a running session. Streams stdout and stderr back and passes the child's exit code through.

| flag | description |
|------|-------------|
| `--socket PATH` | session socket to connect to (default: `hako-session.sock` in the temp dir) |
| `-C`, `--workdir DIR` | working directory for this command (default: the session's) |

### hako session stop

```sh
hako session stop [flags]
```

Stop a running session.

| flag | description |
|------|-------------|
| `--socket PATH` | session socket to stop (default: `hako-session.sock` in the temp dir) |

## Exit codes

- The child's own exit code, passed through untouched.
- `124` on timeout (the process group is killed at the deadline).
- `125` on a hako error (bad policy, sandbox could not start).
- `137` on Linux when a run is OOM-killed at the cgroup memory cap.
