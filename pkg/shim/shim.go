// Package shim handles hako's self-re-execs. Resource limits must be set
// inside the sandbox by the process that becomes the child, never by the
// parent, so hako re-execs itself with a magic first argument and takes
// over before cobra sees anything. On Linux the same mechanism runs the
// namespace init stage.
package shim

import (
	"fmt"
	"os"
	"strconv"

	"github.com/tamnd/hako/pkg/policy"
)

const (
	// ExecCmd marks a re-exec that sets rlimits then execs the target.
	ExecCmd = "__hako_exec"
	// InitCmd marks the Linux namespace init stage.
	InitCmd = "__hako_init"
)

// Init must be called at the very top of main, before any CLI parsing.
// When the process is a shim re-exec it takes over and never returns.
func Init() {
	if len(os.Args) < 2 {
		return
	}
	switch os.Args[1] {
	case ExecCmd:
		runExec(os.Args[2:])
	case InitCmd:
		runInit()
	}
}

// WrapExec builds the argv that re-enters this binary through the exec
// shim: exe __hako_exec k=v... -- argv...
func WrapExec(exe string, l policy.Limits, argv []string) []string {
	out := []string{exe, ExecCmd}
	add := func(k string, v int) {
		if v > 0 {
			out = append(out, k+"="+strconv.Itoa(v))
		}
	}
	add("as", l.MemoryMB)
	add("cpu", l.CPUSeconds)
	add("nproc", l.Processes)
	add("nofile", l.OpenFiles)
	add("fsize", l.FileSizeMB)
	out = append(out, "--")
	return append(out, argv...)
}

func die(code int, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "hako: "+format+"\n", args...)
	os.Exit(code)
}
