---
title: "Overlay and sessions"
description: "Run against a copy-on-write clone and review the diff, and keep one sandbox warm to run many commands through it."
weight: 30
---

## Overlay mode

`--overlay` runs the command against a copy-on-write clone of the working directory instead of the directory itself. The command writes freely into the clone. Your original tree is never touched. When the command finishes, hako prints what changed and where the clone lives, so you can review the diff before applying anything.

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

The marks are `~` for modified, `+` for added, `-` for removed. When nothing changed, hako says so and cleans the clone up.

On macOS the clone is an APFS `clonefile`, so it is near-instant and uses no extra disk until a file is actually written. Elsewhere it is a plain recursive copy. The command sees the clone as its working directory, so relative paths land in the clone. Absolute paths back to the original are still governed by the normal policy.

## Sessions

Starting a sandbox per command is cheap, but sometimes you want many commands to share one box: the same policy, the same working area, the writes from one visible to the next. That is a session.

```sh
# one terminal: start the box (foreground)
hako session start -p dev --overlay

# another terminal: run as many commands as you like against it
hako session exec -- npm install
hako session exec -- npm test
hako session exec -- ./build.sh

# stop it; with --overlay you get the accumulated diff to review
hako session stop
```

`hako session start` holds a resolved policy and a single working area, and runs in the foreground. It takes the same policy flags as `hako run`. Each `exec` runs inside the session's policy and working directory and sees what earlier commands wrote. `exec` streams stdout and stderr back and passes the child's exit code through. Give `exec` its own `-C`/`--workdir` to change directory for that one command.

Commands talk to the server over a unix socket. By default it lives at `hako-session.sock` in the system temp directory. Use `--socket` on `start`, `exec`, and `stop` to place it elsewhere, which is how you run more than one session at once.

```sh
hako session start --socket /tmp/build.sock -p dev
hako session exec --socket /tmp/build.sock -- make
hako session stop --socket /tmp/build.sock
```

### Pairing sessions with overlay

Pair a session with `--overlay` on `start` and the whole sequence of edits lands in one clone. Every `exec` writes into the same clone, later commands see earlier writes, and the original tree stays untouched. On `stop` you get the accumulated diff to review, the same report overlay prints for a single run.
