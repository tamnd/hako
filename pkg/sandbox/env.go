package sandbox

import (
	"os"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/tamnd/hako/pkg/policy"
)

// defaultPass is the environment that always crosses into the sandbox.
// Deliberately small: no cloud credentials, no API tokens.
var defaultPass = []string{
	"PATH", "HOME", "TMPDIR", "TERM", "COLORTERM",
	"LANG", "USER", "LOGNAME", "SHELL", "TZ",
}

// BuildEnv computes the child environment from the policy and the
// current process environment.
func BuildEnv(e policy.Env) []string {
	if e.All {
		env := os.Environ()
		for k, v := range e.Set {
			env = setEnv(env, k, v)
		}
		return env
	}
	var env []string
	for _, kv := range os.Environ() {
		name, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if passes(name, e.Pass) {
			env = append(env, kv)
		}
	}
	for k, v := range e.Set {
		env = setEnv(env, k, v)
	}
	sort.Strings(env)
	return env
}

func passes(name string, extra []string) bool {
	if strings.HasPrefix(name, "LC_") {
		return true
	}
	if slices.Contains(defaultPass, name) {
		return true
	}
	for _, pat := range extra {
		if ok, err := path.Match(pat, name); err == nil && ok {
			return true
		}
	}
	return false
}

func setEnv(env []string, key, val string) []string {
	prefix := key + "="
	for i, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			env[i] = prefix + val
			return env
		}
	}
	return append(env, prefix+val)
}
