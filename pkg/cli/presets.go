package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/tamnd/hako/pkg/policy"
)

func newPresetsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "presets",
		Short: "list built-in policy presets",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			for _, name := range policy.PresetNames() {
				fmt.Fprintf(out, "%-12s %s\n", name, policy.PresetSummary(name))
			}
			return nil
		},
	}
}
