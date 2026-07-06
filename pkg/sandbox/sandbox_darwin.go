package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/tamnd/hako/pkg/policy"
	"github.com/tamnd/hako/pkg/seatbelt"
	"github.com/tamnd/hako/pkg/shim"
)

const sandboxExec = "/usr/bin/sandbox-exec"

func limitsSet(l policy.Limits) bool {
	return l.MemoryMB != 0 || l.CPUSeconds != 0 || l.Processes != 0 ||
		l.OpenFiles != 0 || l.FileSizeMB != 0
}

func run(ctx context.Context, r *policy.Resolved, c Command) (Result, error) {
	argv := c.Argv
	shimExe := ""
	if limitsSet(r.Limits) {
		exe, err := os.Executable()
		if err != nil {
			return Result{ExitCode: ExitError}, fmt.Errorf("sandbox: locate self for shim: %w", err)
		}
		shimExe = exe
		argv = shim.WrapExec(exe, r.Limits, argv)
	}

	profile, err := seatbelt.Profile(r, shimExe)
	if err != nil {
		return Result{ExitCode: ExitError}, err
	}
	pf, err := os.CreateTemp("", "hako-*.sb")
	if err != nil {
		return Result{ExitCode: ExitError}, err
	}
	defer os.Remove(pf.Name())
	if _, err := pf.WriteString(profile); err != nil {
		pf.Close()
		return Result{ExitCode: ExitError}, err
	}
	pf.Close()

	args := append([]string{"-f", pf.Name()}, argv...)
	cmd := exec.CommandContext(ctx, sandboxExec, args...)
	cmd.Dir = c.Dir
	cmd.Env = BuildEnv(r.Env)
	cmd.Stdin = c.Stdin
	cmd.Stdout = c.Stdout
	cmd.Stderr = c.Stderr
	// Own process group so a timeout kills the whole tree, not just
	// sandbox-exec.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 3 * time.Second
	return wait(ctx, cmd)
}
