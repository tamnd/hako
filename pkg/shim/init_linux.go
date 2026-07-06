package shim

import (
	"os"
	"os/exec"
	"os/signal"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/tamnd/hako/pkg/nsbox"
)

// runInit is pid 1 inside the fresh namespaces: build the root, apply
// limits, then run the target as a child and act as init for it.
func runInit() {
	spec, err := nsbox.DecodeEnv()
	if err != nil {
		die(125, "init: %v", err)
	}
	os.Unsetenv(nsbox.EnvSpec)
	if err := nsbox.Setup(spec); err != nil {
		die(125, "init: %v", err)
	}
	if err := ApplyLimits(spec.Limits); err != nil {
		die(125, "init: setrlimit: %v", err)
	}
	os.Clearenv()
	for _, kv := range spec.Env {
		if k, v, ok := cutEnv(kv); ok {
			os.Setenv(k, v)
		}
	}
	os.Exit(reap(spec.Argv))
}

// reap runs argv as a child of this pid-1 process, forwards signals,
// and collects every orphan the namespace re-parents onto us. Exec'ing
// the target directly would make it pid 1 with default-ignored signals
// and no reaper.
func reap(argv []string) int {
	path := argv[0]
	if !strings.Contains(path, "/") {
		p, err := exec.LookPath(path)
		if err != nil {
			die(127, "%s: command not found", argv[0])
		}
		path = p
	}
	cmd := exec.Command(path, argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		die(126, "%s: %v", argv[0], err)
	}

	sigs := make(chan os.Signal, 16)
	signal.Notify(sigs)
	go func() {
		for s := range sigs {
			if s == unix.SIGCHLD {
				continue
			}
			cmd.Process.Signal(s)
		}
	}()

	code := 0
	for {
		var ws unix.WaitStatus
		pid, err := unix.Wait4(-1, &ws, 0, nil)
		switch {
		case err == unix.ECHILD:
			return code
		case err == unix.EINTR:
			continue
		case err != nil:
			return code
		case pid == cmd.Process.Pid:
			if ws.Signaled() {
				code = 128 + int(ws.Signal())
			} else {
				code = ws.ExitStatus()
			}
		}
	}
}

func cutEnv(kv string) (string, string, bool) {
	for i := 0; i < len(kv); i++ {
		if kv[i] == '=' {
			return kv[:i], kv[i+1:], true
		}
	}
	return "", "", false
}
