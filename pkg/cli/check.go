package cli

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tamnd/hako/pkg/seatbelt"
)

func newCheckCmd() *cobra.Command {
	var f policyFlags
	var showProfile bool
	cmd := &cobra.Command{
		Use:   "check [flags]",
		Short: "print the effective policy without running anything",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			r, dir, err := f.resolve(cmd)
			if err != nil {
				return err
			}
			if showProfile {
				if runtime.GOOS != "darwin" {
					return fmt.Errorf("--profile dumps the Seatbelt profile, darwin only")
				}
				p, err := seatbelt.Profile(r, "")
				if err != nil {
					return err
				}
				fmt.Print(p)
				return nil
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "policy   %s\n", r.Name)
			fmt.Fprintf(out, "workdir  %s\n", dir)
			fmt.Fprintf(out, "network  %s\n", onOff(r.Net))
			list := func(label string, paths []string) {
				if len(paths) == 0 {
					fmt.Fprintf(out, "%-8s (none)\n", label)
					return
				}
				fmt.Fprintf(out, "%-8s %s\n", label, paths[0])
				for _, p := range paths[1:] {
					fmt.Fprintf(out, "         %s\n", p)
				}
			}
			list("read", r.Read)
			list("write", r.Write)
			list("deny", r.Deny)
			var lims []string
			add := func(s string, v int, unit string) {
				if v > 0 {
					lims = append(lims, fmt.Sprintf("%s %d%s", s, v, unit))
				}
			}
			if r.Limits.Timeout.Duration > 0 {
				lims = append(lims, "timeout "+r.Limits.Timeout.String())
			}
			add("mem", r.Limits.MemoryMB, "MB")
			add("cpu", r.Limits.CPUSeconds, "s")
			add("procs", r.Limits.Processes, "")
			add("files", r.Limits.OpenFiles, "")
			add("fsize", r.Limits.FileSizeMB, "MB")
			if len(lims) == 0 {
				lims = []string{"(none)"}
			}
			fmt.Fprintf(out, "limits   %s\n", strings.Join(lims, ", "))
			return nil
		},
	}
	addPolicyFlags(cmd, &f)
	cmd.Flags().BoolVar(&showProfile, "profile", false, "dump the generated Seatbelt profile (darwin)")
	return cmd
}

func onOff(b bool) string {
	if b {
		return "allowed"
	}
	return "blocked"
}
