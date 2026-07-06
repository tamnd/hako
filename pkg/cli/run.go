package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/tamnd/hako/pkg/audit"
	"github.com/tamnd/hako/pkg/overlay"
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
	var ov *overlay.Overlay
	if f.overlay {
		ov, err = overlay.Materialize(dir)
		if err != nil {
			return fmt.Errorf("overlay: %w", err)
		}
		// Run inside the clone and let it be written; the original tree
		// stays as it was.
		dir = ov.Dir
		r.Read = append(r.Read, ov.Dir)
		r.Write = append(r.Write, ov.Dir)
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
	if ov != nil {
		reportOverlay(ov)
	}
	os.Exit(res.ExitCode)
	return nil
}

// reportOverlay prints what the command changed in the clone and where
// the clone lives, so the user can review or apply it. On an error, or
// when nothing changed, it cleans the clone up.
func reportOverlay(ov *overlay.Overlay) {
	changes, err := ov.Diff()
	if err != nil {
		fmt.Fprintf(os.Stderr, "hako: overlay diff: %v\n", err)
		return
	}
	if len(changes) == 0 {
		fmt.Fprintln(os.Stderr, "hako: overlay: no changes")
		ov.Cleanup()
		return
	}
	fmt.Fprintf(os.Stderr, "hako: overlay: %d change(s)\n", len(changes))
	for _, c := range changes {
		mark := map[overlay.ChangeKind]string{
			overlay.Added: "+", overlay.Modified: "~", overlay.Removed: "-",
		}[c.Kind]
		fmt.Fprintf(os.Stderr, "  %s %s\n", mark, c.Path)
	}
	fmt.Fprintf(os.Stderr, "review the writes at: %s\n", ov.Dir)
}
