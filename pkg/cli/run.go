package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/tamnd/hako/pkg/audit"
	"github.com/tamnd/hako/pkg/sandbox"
)

func newRunCmd() *cobra.Command {
	var f policyFlags
	cmd := &cobra.Command{
		Use:   "run [flags] -- command [args...]",
		Short: "run a command inside the sandbox",
		Example: "  hako run -- npm test\n" +
			"  hako run -p restricted -- ./agent-task.sh\n" +
			"  hako run --net --timeout 5m --mem 1024 -- python fetch.py",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInSandbox(cmd, &f, args)
		},
	}
	cmd.Flags().SetInterspersed(false)
	addPolicyFlags(cmd, &f)
	return cmd
}

func newShellCmd() *cobra.Command {
	var f policyFlags
	cmd := &cobra.Command{
		Use:   "shell [flags]",
		Short: "open your shell inside the sandbox",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			sh := os.Getenv("SHELL")
			if sh == "" {
				sh = "/bin/sh"
			}
			return runInSandbox(cmd, &f, []string{sh})
		},
	}
	addPolicyFlags(cmd, &f)
	return cmd
}

// runInSandbox resolves the policy, runs the command, and exits the
// process with the child's exit code. It only returns on setup errors.
func runInSandbox(cmd *cobra.Command, f *policyFlags, argv []string) error {
	r, dir, err := f.resolve(cmd)
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	if r.Limits.Timeout.Duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.Limits.Timeout.Duration)
		defer cancel()
	}
	var auditor *audit.Logger
	if f.audit != "" {
		auditor, err = audit.Open(f.audit)
		if err != nil {
			return fmt.Errorf("open audit log: %w", err)
		}
		defer auditor.Close()
	}
	res, err := sandbox.Run(ctx, r, sandbox.Command{
		Argv:   argv,
		Dir:    dir,
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Audit:  auditor,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "hako: %v\n", err)
		os.Exit(sandbox.ExitError)
	}
	if res.TimedOut {
		fmt.Fprintf(os.Stderr, "hako: timed out after %s\n", r.Limits.Timeout.Duration)
	}
	os.Exit(res.ExitCode)
	return nil
}
