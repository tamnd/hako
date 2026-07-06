---
title: "Installation"
description: "Install hako with Homebrew, from Linux packages, from a prebuilt archive, or with go install."
weight: 20
---

hako runs on macOS and Linux. On Linux it needs an unprivileged-user-namespace kernel, which most distributions have shipped since 5.10.

## Homebrew (macOS)

```sh
brew install tamnd/tap/hako
```

## Linux packages

Grab the package for your distribution from the [releases page](https://github.com/tamnd/hako/releases) and install it.

```sh
# Debian/Ubuntu
sudo dpkg -i hako_*_amd64.deb
# Fedora/RHEL
sudo rpm -i hako-*.x86_64.rpm
# Alpine
sudo apk add --allow-untrusted hako_*_x86_64.apk
```

## Prebuilt archives

Download a prebuilt archive for your OS and architecture from the [releases page](https://github.com/tamnd/hako/releases), unpack it, and put the `hako` binary on your `PATH`.

## From source

```sh
go install github.com/tamnd/hako@latest
```

## Windows

Windows is not supported. hako sandboxes with host facilities that Windows does not offer. Run it inside WSL, where it uses the Linux backend.

## Linux kernel requirement

The Linux backend clones into a fresh user namespace without root. That needs unprivileged user namespaces enabled, which is the default on most kernels since 5.10. If `hako run` reports that user namespaces are unavailable, your kernel or distribution has them switched off, and you will need to enable them (for example `kernel.unprivileged_userns_clone=1` on distributions that gate it).
