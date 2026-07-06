// Package sandbox runs a command under the OS sandbox described by a
// resolved policy. On macOS it generates a Seatbelt profile and execs
// through sandbox-exec; on Linux it isolates with namespaces.
//
// Embedders must call shim.Init() at the top of main: hako re-execs
// itself inside the sandbox to apply rlimits (and as namespace init on
// Linux), and shim.Init is the hook that catches those re-execs.
package sandbox

import (
	"context"
	"errors"
	"io"
	"os/exec"

	"github.com/tamnd/hako/pkg/audit"
	"github.com/tamnd/hako/pkg/policy"
)

// Command is what to run inside the sandbox.
type Command struct {
	// Argv is the program and its arguments. Argv[0] is looked up in
	// PATH from the scrubbed environment when it has no slash.
	Argv []string
	// Dir is the working directory. It should be readable under the
	// policy or the child will fail to start.
	Dir string
	// Stdio streams. Nil means inherit nothing (empty stdin, discarded
	// output).
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Audit, when set, receives a record of the run and of every access
	// the sandbox refused. Nil disables auditing.
	Audit *audit.Logger
}

// Result reports how the child ended.
type Result struct {
	ExitCode int
	TimedOut bool
}

// Conventional exit codes, following timeout(1) and shell convention.
const (
	ExitTimeout = 124
	ExitError   = 125
)

// Run executes c under the sandbox policy r and blocks until it exits.
// The child's exit code is passed through in Result. A context deadline
// kills the whole process group and reports ExitTimeout.
func Run(ctx context.Context, r *policy.Resolved, c Command) (Result, error) {
	if len(c.Argv) == 0 {
		return Result{ExitCode: ExitError}, errors.New("sandbox: empty argv")
	}
	return run(ctx, r, c)
}

// auditStart records what the sandbox was asked to run and under which
// policy. It is a no-op when auditing is off.
func auditStart(c Command, r *policy.Resolved) {
	c.Audit.Log("run.start", map[string]any{
		"argv":   c.Argv,
		"dir":    c.Dir,
		"net":    r.Net,
		"hosts":  r.Hosts,
		"reads":  len(r.Read),
		"writes": len(r.Write),
		"denies": len(r.Deny),
	})
}

// auditEnd records how the run finished.
func auditEnd(c Command, res Result) {
	c.Audit.Log("run.end", map[string]any{
		"exit_code": res.ExitCode,
		"timed_out": res.TimedOut,
	})
}

// wait runs the prepared command and translates the exit status.
func wait(ctx context.Context, cmd *exec.Cmd) (Result, error) {
	err := cmd.Run()
	timedOut := ctx.Err() != nil
	if err == nil {
		return Result{ExitCode: 0}, nil
	}
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		if timedOut {
			return Result{ExitCode: ExitTimeout, TimedOut: true}, nil
		}
		return Result{ExitCode: ee.ExitCode()}, nil
	}
	if timedOut {
		return Result{ExitCode: ExitTimeout, TimedOut: true}, nil
	}
	return Result{ExitCode: ExitError}, err
}
