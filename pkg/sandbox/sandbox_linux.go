package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/tamnd/hako/pkg/nsbox"
	"github.com/tamnd/hako/pkg/policy"
	"github.com/tamnd/hako/pkg/shim"
)

func run(ctx context.Context, r *policy.Resolved, c Command) (Result, error) {
	spec := nsbox.Spec{
		Argv:   c.Argv,
		Dir:    c.Dir,
		Env:    BuildEnv(r.Env),
		Read:   r.Read,
		Write:  r.Write,
		Deny:   r.Deny,
		Net:    r.Net,
		Limits: r.Limits,
	}
	enc, err := spec.Encode()
	if err != nil {
		return Result{ExitCode: ExitError}, err
	}

	cmd := exec.CommandContext(ctx, "/proc/self/exe", shim.InitCmd)
	cmd.Env = []string{nsbox.EnvSpec + "=" + enc}
	cmd.Stdin = c.Stdin
	cmd.Stdout = c.Stdout
	cmd.Stderr = c.Stderr

	flags := syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS |
		syscall.CLONE_NEWPID | syscall.CLONE_NEWUTS | syscall.CLONE_NEWIPC
	if !r.Net {
		flags |= syscall.CLONE_NEWNET
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: uintptr(flags),
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
		// Killing init (namespace pid 1) tears down the whole tree.
		Pdeathsig: syscall.SIGKILL,
	}
	cmd.WaitDelay = 3 * time.Second
	res, err := wait(ctx, cmd)
	if err != nil && errors.Is(err, os.ErrPermission) {
		err = fmt.Errorf("%w\ncreating user namespaces seems to be blocked; "+
			"on Ubuntu 24.04+ try: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0", err)
	}
	return res, err
}
