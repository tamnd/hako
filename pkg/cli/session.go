package cli

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/tamnd/hako/pkg/overlay"
	"github.com/tamnd/hako/pkg/session"
)

func defaultSocket() string {
	return filepath.Join(os.TempDir(), "hako-session.sock")
}

func newSessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "keep one sandbox warm and run many commands through it",
		Long: "A session holds a resolved policy and a single working area.\n" +
			"Start it once, then exec as many commands as you like against\n" +
			"the same box; each command sees the writes the last one made.\n" +
			"With --overlay the writes accumulate in a clone you review on stop.",
	}
	cmd.AddCommand(newSessionStartCmd(), newSessionExecCmd(), newSessionStopCmd())
	return cmd
}

func newSessionStartCmd() *cobra.Command {
	var f policyFlags
	var socket string
	cmd := &cobra.Command{
		Use:   "start [flags]",
		Short: "start a session server (runs in the foreground)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
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
				dir = ov.Dir
				r.Read = append(r.Read, ov.Dir)
				r.Write = append(r.Write, ov.Dir)
			}
			srv, err := session.Listen(socket, r, dir)
			if err != nil {
				return err
			}
			defer srv.Close()

			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			fmt.Fprintf(os.Stderr, "hako: session listening on %s\n", srv.Socket())
			fmt.Fprintf(os.Stderr, "hako: exec with:  hako session exec --socket %s -- <cmd>\n", srv.Socket())

			serveErr := make(chan error, 1)
			go func() { serveErr <- srv.Serve(ctx) }()
			select {
			case <-ctx.Done():
			case err := <-serveErr:
				if err != nil {
					return err
				}
			}
			if ov != nil {
				reportOverlay(ov)
			}
			return nil
		},
	}
	addPolicyFlags(cmd, &f)
	cmd.Flags().StringVar(&socket, "socket", defaultSocket(), "unix socket path for the session")
	return cmd
}

func newSessionExecCmd() *cobra.Command {
	var socket string
	var workdir string
	cmd := &cobra.Command{
		Use:   "exec [flags] -- command [args...]",
		Short: "run a command in a running session",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			code, err := session.Exec(socket, args, workdir, os.Stdout, os.Stderr)
			if err != nil {
				return err
			}
			os.Exit(code)
			return nil
		},
	}
	cmd.Flags().SetInterspersed(false)
	cmd.Flags().StringVar(&socket, "socket", defaultSocket(), "session socket to connect to")
	cmd.Flags().StringVarP(&workdir, "workdir", "C", "", "working directory for this command (default: the session's)")
	return cmd
}

func newSessionStopCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "stop",
		Short: "stop a running session",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := session.Stop(socket); err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "hako: session stopped")
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", defaultSocket(), "session socket to stop")
	return cmd
}
