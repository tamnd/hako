//go:build darwin || linux

package shim

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/tamnd/hako/pkg/policy"
)

// runExec parses "k=v ... -- argv...", applies rlimits, and replaces
// this process with the target. Exit codes follow shell convention:
// 127 not found, 126 not executable, 125 anything else.
func runExec(args []string) {
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 || sep == len(args)-1 {
		die(125, "shim: malformed exec args")
	}
	var l policy.Limits
	for _, kv := range args[:sep] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			die(125, "shim: bad limit %q", kv)
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			die(125, "shim: bad limit %q", kv)
		}
		switch k {
		case "as":
			l.MemoryMB = n
		case "cpu":
			l.CPUSeconds = n
		case "nproc":
			l.Processes = n
		case "nofile":
			l.OpenFiles = n
		case "fsize":
			l.FileSizeMB = n
		default:
			die(125, "shim: unknown limit %q", k)
		}
	}
	if err := ApplyLimits(l); err != nil {
		die(125, "shim: setrlimit: %v", err)
	}
	ExecInto(args[sep+1:])
}

// ApplyLimits sets rlimits on the current process. Zero fields are left
// untouched.
func ApplyLimits(l policy.Limits) error {
	set := func(res int, v uint64) error {
		if v == 0 {
			return nil
		}
		return unix.Setrlimit(res, &unix.Rlimit{Cur: v, Max: v})
	}
	const mb = 1 << 20
	if err := set(unix.RLIMIT_AS, uint64(l.MemoryMB)*mb); err != nil {
		return err
	}
	if err := set(unix.RLIMIT_CPU, uint64(l.CPUSeconds)); err != nil {
		return err
	}
	if err := set(rlimitNproc, uint64(l.Processes)); err != nil {
		return err
	}
	if err := set(unix.RLIMIT_NOFILE, uint64(l.OpenFiles)); err != nil {
		return err
	}
	return set(unix.RLIMIT_FSIZE, uint64(l.FileSizeMB)*mb)
}

// ExecInto replaces the current process with argv, resolving argv[0]
// against PATH from the current environment. Never returns.
func ExecInto(argv []string) {
	path := argv[0]
	if !strings.Contains(path, "/") {
		p, err := exec.LookPath(path)
		if err != nil {
			die(127, "%s: command not found", argv[0])
		}
		path = p
	}
	err := unix.Exec(path, argv, os.Environ())
	if errors.Is(err, unix.EACCES) || errors.Is(err, unix.ENOEXEC) {
		die(126, "%s: cannot execute: %v", argv[0], err)
	}
	die(127, "%s: %v", argv[0], err)
}
