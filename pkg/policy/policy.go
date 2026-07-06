// Package policy defines what a sandboxed command may touch: filesystem
// paths, network, resource limits, and environment. A Policy comes from a
// preset, a TOML file, CLI flags, or a merge of all three, and is turned
// into a Resolved policy before a backend consumes it.
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Duration wraps time.Duration so TOML can say timeout = "5m".
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// FS lists filesystem access. Read and Write are allowlists of paths
// (files or directory subtrees). Deny always wins, even over Write.
type FS struct {
	Read  []string `toml:"read"`
	Write []string `toml:"write"`
	Deny  []string `toml:"deny"`
	// NoDefaultDeny disables the built-in secrets deny list. Almost
	// never what you want for agent workloads.
	NoDefaultDeny bool `toml:"no_default_deny"`
}

// Net controls network access. Nil Allow means "inherit" during merges
// and false once resolved.
type Net struct {
	Allow *bool `toml:"allow"`
}

// Limits are resource ceilings for the child. Zero means unlimited.
type Limits struct {
	Timeout    Duration `toml:"timeout"`
	MemoryMB   int      `toml:"memory_mb"`
	CPUSeconds int      `toml:"cpu_seconds"`
	Processes  int      `toml:"processes"`
	OpenFiles  int      `toml:"open_files"`
	FileSizeMB int      `toml:"file_size_mb"`
}

// Env controls what environment the child sees. By default only a small
// safe set (PATH, HOME, TERM, ...) passes through.
type Env struct {
	// Pass adds variable names (globs allowed, e.g. "GO*") to the
	// pass-through set.
	Pass []string `toml:"pass"`
	// Set forces variables to given values.
	Set map[string]string `toml:"set"`
	// All passes the entire parent environment. Risky: tokens in env
	// leak into the sandbox.
	All bool `toml:"all"`
}

// Policy is the user-facing sandbox description.
type Policy struct {
	Name   string `toml:"name"`
	FS     FS     `toml:"fs"`
	Net    Net    `toml:"net"`
	Limits Limits `toml:"limits"`
	Env    Env    `toml:"env"`
}

// Resolved is a policy after expansion: absolute deduped paths, write
// folded into read, default denies applied. Backends consume this.
type Resolved struct {
	Name   string
	Read   []string
	Write  []string
	Deny   []string
	Net    bool
	Limits Limits
	Env    Env
}

// Load reads a TOML policy file. Relative paths inside the file resolve
// against the file's directory.
func Load(path string) (*Policy, error) {
	var p Policy
	meta, err := toml.DecodeFile(path, &p)
	if err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	if un := meta.Undecoded(); len(un) > 0 {
		return nil, fmt.Errorf("policy %s: unknown key %q", path, un[0].String())
	}
	base, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	p.FS.Read = Expand(p.FS.Read, base)
	p.FS.Write = Expand(p.FS.Write, base)
	p.FS.Deny = Expand(p.FS.Deny, base)
	if p.Name == "" {
		p.Name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	return &p, nil
}

// Expand normalizes paths: ~ and env vars expand, relative paths join
// base, everything comes out clean and absolute.
func Expand(paths []string, base string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if p == "" {
			continue
		}
		p = os.ExpandEnv(p)
		if p == "~" {
			p = home()
		} else if strings.HasPrefix(p, "~/") {
			p = filepath.Join(home(), p[2:])
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(base, p)
		}
		out = append(out, filepath.Clean(p))
	}
	return out
}

// Merge folds src into dst. Paths and env accumulate, scalar settings in
// src win when set.
func Merge(dst, src *Policy) {
	if src.Name != "" {
		dst.Name = src.Name
	}
	dst.FS.Read = append(dst.FS.Read, src.FS.Read...)
	dst.FS.Write = append(dst.FS.Write, src.FS.Write...)
	dst.FS.Deny = append(dst.FS.Deny, src.FS.Deny...)
	if src.FS.NoDefaultDeny {
		dst.FS.NoDefaultDeny = true
	}
	if src.Net.Allow != nil {
		dst.Net.Allow = src.Net.Allow
	}
	if src.Limits.Timeout.Duration != 0 {
		dst.Limits.Timeout = src.Limits.Timeout
	}
	if src.Limits.MemoryMB != 0 {
		dst.Limits.MemoryMB = src.Limits.MemoryMB
	}
	if src.Limits.CPUSeconds != 0 {
		dst.Limits.CPUSeconds = src.Limits.CPUSeconds
	}
	if src.Limits.Processes != 0 {
		dst.Limits.Processes = src.Limits.Processes
	}
	if src.Limits.OpenFiles != 0 {
		dst.Limits.OpenFiles = src.Limits.OpenFiles
	}
	if src.Limits.FileSizeMB != 0 {
		dst.Limits.FileSizeMB = src.Limits.FileSizeMB
	}
	dst.Env.Pass = append(dst.Env.Pass, src.Env.Pass...)
	if src.Env.All {
		dst.Env.All = true
	}
	for k, v := range src.Env.Set {
		if dst.Env.Set == nil {
			dst.Env.Set = map[string]string{}
		}
		dst.Env.Set[k] = v
	}
}

// Resolve produces the effective policy a backend runs with.
func (p *Policy) Resolve() (*Resolved, error) {
	r := &Resolved{
		Name:   p.Name,
		Read:   slices.Clone(p.FS.Read),
		Write:  slices.Clone(p.FS.Write),
		Deny:   slices.Clone(p.FS.Deny),
		Limits: p.Limits,
		Env:    p.Env,
	}
	if p.Net.Allow != nil {
		r.Net = *p.Net.Allow
	}
	// Writing implies reading.
	r.Read = append(r.Read, r.Write...)
	if !p.FS.NoDefaultDeny {
		r.Deny = append(r.Deny, DefaultDeny()...)
	}
	// Sandbox backends match real paths, so /tmp and /var symlinks
	// (macOS) must resolve before they reach a profile.
	r.Read = dedup(realpaths(r.Read))
	r.Write = dedup(realpaths(r.Write))
	r.Deny = dedup(realpaths(r.Deny))
	for _, set := range [][]string{r.Read, r.Write, r.Deny} {
		for _, path := range set {
			if !filepath.IsAbs(path) {
				return nil, fmt.Errorf("policy path %q is not absolute; run Expand first", path)
			}
			if strings.ContainsAny(path, "\n\r") {
				return nil, fmt.Errorf("policy path %q contains a newline", path)
			}
		}
	}
	return r, nil
}

// DefaultDeny is the built-in secrets deny list. It applies even when
// read allows the whole filesystem.
func DefaultDeny() []string {
	h := home()
	rel := []string{
		".ssh", ".aws", ".gnupg", ".netrc", ".npmrc", ".pypirc",
		".docker", ".kube", ".azure",
		".config/gh", ".config/gcloud",
		".cargo/credentials", ".cargo/credentials.toml",
		"Library/Keychains",
	}
	out := make([]string, 0, len(rel))
	for _, r := range rel {
		out = append(out, filepath.Join(h, r))
	}
	return out
}

func realpaths(in []string) []string {
	for i, p := range in {
		if rp, err := filepath.EvalSymlinks(p); err == nil {
			in[i] = rp
		}
	}
	return in
}

func dedup(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func home() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "/"
}
