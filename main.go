package main

import (
	"github.com/tamnd/hako/pkg/cli"
	"github.com/tamnd/hako/pkg/shim"
)

var version = "dev"

func main() {
	// Must run first: when hako re-execs itself inside the sandbox to set
	// rlimits (or as namespace init on Linux), shim.Init takes over and
	// never returns.
	shim.Init()
	cli.Execute(version)
}
