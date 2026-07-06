---
title: "Networking"
description: "The three network modes: offline by default, host allowlist through a CONNECT proxy (macOS only), and full open network."
weight: 20
---

hako has three network modes, cheapest first. Pick the tightest one that lets the command do its job.

## Offline (default)

No network at all. This is what you get unless the policy says otherwise. On Linux the command runs in its own network namespace with only loopback up, so there is no route to anything. On macOS the Seatbelt profile denies network operations.

```sh
hako run -- npm test
```

## Allowlist (macOS only)

Name the hosts the command may reach and refuse everything else. The command's traffic is funnelled through a small CONNECT proxy that only dials the hosts you name. The sandbox itself is confined to loopback, so it cannot reach anything else even by raw IP. The only address it can open directly is the proxy.

```sh
hako run --allow-host api.openai.com --allow-host '*.githubusercontent.com' -- ./agent
```

Or in a `.hako.toml`:

```toml
[net]
allow_hosts = ["api.openai.com", "*.githubusercontent.com"]
```

Each entry is one of:

- a bare host (`example.com`), matching that host on any port,
- a host with a port pin (`api.example.com:443`), matching only that port,
- a subdomain wildcard (`*.example.com`), which matches `a.example.com` but not the apex `example.com`.

`allow_hosts` implies network access even when `allow` is false, because reaching the proxy is a network operation. It does not open the network beyond the named hosts.

This is enforced on macOS only. On Linux a run with a host allowlist errors out rather than pretend to enforce it: the fresh network namespace cannot see the parent's proxy yet. Use full open network on Linux, or run the allowlist on macOS.

## Open (full network)

Full network, no mediation. Use it when a command needs to reach many hosts and an allowlist is impractical.

```sh
hako run --net -- python fetch.py
```

Or:

```toml
[net]
allow = true
```

`--net` and `allow = true` are the widest network setting. On Linux this is also the way to give a command network at all, since the allowlist is not wired for the fresh netns. Prefer the allowlist on macOS whenever you can name the hosts.
