package shim

import (
	"os"

	"github.com/tamnd/hako/pkg/nsbox"
)

// runInit is pid 1 inside the fresh namespaces: build the root, apply
// limits, exec the target.
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
	ExecInto(spec.Argv)
}

func cutEnv(kv string) (string, string, bool) {
	for i := 0; i < len(kv); i++ {
		if kv[i] == '=' {
			return kv[:i], kv[i+1:], true
		}
	}
	return "", "", false
}
