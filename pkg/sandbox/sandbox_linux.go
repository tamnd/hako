package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

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

	cg, err := nsbox.PrepareCgroup(r.Limits)
	if err != nil {
		return Result{ExitCode: ExitError}, err
	}
	defer cg.Cleanup()

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
	attr := &syscall.SysProcAttr{
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
	if fd := cg.FD(); fd >= 0 {
		attr.UseCgroupFD = true
		attr.CgroupFD = fd
	}
	cmd.SysProcAttr = attr
	cmd.WaitDelay = 3 * time.Second

	res, err := wait(ctx, cmd)
	// clone3 into a cgroup fails on delegated-but-unusable trees
	// (EOPNOTSUPP/EINVAL) before the child ever starts. Cgroups are a
	// bonus over rlimits, never a regression: on such a failure, drop
	// the cgroup and run again the plain way.
	if err != nil && attr.UseCgroupFD && cloneRejected(err) {
		cg.Cleanup()
		attr.UseCgroupFD = false
		attr.CgroupFD = 0
		retry := exec.CommandContext(ctx, "/proc/self/exe", shim.InitCmd)
		retry.Env = cmd.Env
		retry.Stdin, retry.Stdout, retry.Stderr = c.Stdin, c.Stdout, c.Stderr
		retry.SysProcAttr = attr
		retry.WaitDelay = 3 * time.Second
		res, err = wait(ctx, retry)
	}
	if err != nil && errors.Is(err, os.ErrPermission) {
		err = fmt.Errorf("%w\ncreating user namespaces seems to be blocked; "+
			"on Ubuntu 24.04+ try: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0", err)
	}
	return res, err
}

// cloneRejected reports whether the error is the kernel refusing the
// clone before exec, as opposed to the child running and failing.
func cloneRejected(err error) bool {
	return errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.EBUSY)
}
