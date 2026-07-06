package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/tamnd/hako/pkg/policy"
)

const localPolicy = ".hako.toml"

type policyFlags struct {
	policy  string
	ro      []string
	rw      []string
	deny      []string
	net       bool
	allowHost []string
	timeout   time.Duration
	mem     int
	cpu     int
	procs   int
	files   int
	workdir string
	env     []string
	passEnv []string
	allEnv  bool
	audit   string
}

func addPolicyFlags(cmd *cobra.Command, f *policyFlags) {
	fl := cmd.Flags()
	fl.StringVarP(&f.policy, "policy", "p", "", "policy file or preset name (default: ./.hako.toml, else \"standard\")")
	fl.StringArrayVar(&f.ro, "ro", nil, "allow reading this path (repeatable)")
	fl.StringArrayVar(&f.rw, "rw", nil, "allow writing this path (repeatable)")
	fl.StringArrayVar(&f.deny, "deny", nil, "deny this path even if otherwise allowed (repeatable)")
	fl.BoolVar(&f.net, "net", false, "allow unrestricted network access")
	fl.StringArrayVar(&f.allowHost, "allow-host", nil, "allow network only to this host, via a local proxy (repeatable; host or host:port, *.domain ok)")
	fl.DurationVar(&f.timeout, "timeout", 0, "kill the command after this long (e.g. 5m)")
	fl.IntVar(&f.mem, "mem", 0, "memory ceiling in MB (cgroup on Linux, RLIMIT_AS on macOS)")
	fl.IntVar(&f.cpu, "cpu", 0, "CPU time ceiling in seconds")
	fl.IntVar(&f.procs, "procs", 0, "max processes")
	fl.IntVar(&f.files, "files", 0, "max open files")
	fl.StringVarP(&f.workdir, "workdir", "C", "", "working directory inside the sandbox")
	fl.StringArrayVar(&f.env, "env", nil, "set KEY=VALUE in the child environment (repeatable)")
	fl.StringArrayVar(&f.passEnv, "pass-env", nil, "pass this env var through (glob ok, repeatable)")
	fl.BoolVar(&f.allEnv, "all-env", false, "pass the entire environment through (leaks tokens, be sure)")
	fl.StringVar(&f.audit, "audit", "", "append a JSONL record of the run and every denied access to this file")
}

// resolve turns preset/file/flags into the effective policy plus the
// working directory for the child.
func (f *policyFlags) resolve(cmd *cobra.Command) (*policy.Resolved, string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, "", err
	}

	var base *policy.Policy
	switch {
	case f.policy != "":
		if p, ok := policy.Preset(f.policy, cwd); ok {
			base = p
		} else if _, err := os.Stat(f.policy); err == nil {
			base, err = policy.Load(f.policy)
			if err != nil {
				return nil, "", err
			}
		} else {
			return nil, "", fmt.Errorf("--policy %q: not a preset (%s) and not a file",
				f.policy, strings.Join(policy.PresetNames(), ", "))
		}
	default:
		if _, err := os.Stat(localPolicy); err == nil {
			base, err = policy.Load(localPolicy)
			if err != nil {
				return nil, "", err
			}
		} else {
			base, _ = policy.Preset("standard", cwd)
		}
	}

	over := &policy.Policy{}
	over.FS.Read = policy.Expand(f.ro, cwd)
	over.FS.Write = policy.Expand(f.rw, cwd)
	over.FS.Deny = policy.Expand(f.deny, cwd)
	if cmd.Flags().Changed("net") {
		net := f.net
		over.Net.Allow = &net
	}
	over.Net.AllowHosts = f.allowHost
	over.Limits = policy.Limits{
		Timeout:    policy.Duration{Duration: f.timeout},
		MemoryMB:   f.mem,
		CPUSeconds: f.cpu,
		Processes:  f.procs,
		OpenFiles:  f.files,
	}
	over.Env.Pass = f.passEnv
	over.Env.All = f.allEnv
	for _, kv := range f.env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, "", fmt.Errorf("--env %q: want KEY=VALUE", kv)
		}
		if over.Env.Set == nil {
			over.Env.Set = map[string]string{}
		}
		over.Env.Set[k] = v
	}
	policy.Merge(base, over)

	r, err := base.Resolve()
	if err != nil {
		return nil, "", err
	}
	dir := cwd
	if f.workdir != "" {
		dir = policy.Expand([]string{f.workdir}, cwd)[0]
	}
	return r, dir, nil
}
