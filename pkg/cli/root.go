// Package cli wires the hako commands.
package cli

import (
	"context"
	"os"

	"github.com/charmbracelet/fang"
	"github.com/spf13/cobra"
)

// Execute runs the CLI. It does not return on `hako run`: the child's
// exit code is passed straight to os.Exit.
func Execute(version string) {
	root := &cobra.Command{
		Use:   "hako",
		Short: "a little box to run AI agents in",
		Long: "hako (箱) runs a command inside an OS-level sandbox.\n" +
			"Filesystem, network, and resource access come from a policy:\n" +
			"a built-in preset, a .hako.toml file, or flags.",
		SilenceUsage: true,
	}
	root.AddCommand(newRunCmd(), newShellCmd(), newCheckCmd(), newPresetsCmd())
	if err := fang.Execute(context.Background(), root, fang.WithVersion(version)); err != nil {
		os.Exit(1)
	}
}
