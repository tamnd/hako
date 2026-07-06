package policy

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestLoadTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.toml")
	body := `
name = "agent"
[fs]
read = ["/usr", "src"]
write = ["out"]
deny = ["~/.ssh"]
[net]
allow = true
[limits]
timeout = "90s"
memory_mb = 256
[env]
pass = ["GO*"]
[env.set]
CI = "1"
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "agent" {
		t.Errorf("name = %q", p.Name)
	}
	if want := filepath.Join(dir, "src"); !slices.Contains(p.FS.Read, want) {
		t.Errorf("relative read not resolved against file dir: %v", p.FS.Read)
	}
	home, _ := os.UserHomeDir()
	if want := filepath.Join(home, ".ssh"); !slices.Contains(p.FS.Deny, want) {
		t.Errorf("tilde not expanded: %v", p.FS.Deny)
	}
	if p.Net.Allow == nil || !*p.Net.Allow {
		t.Error("net.allow not parsed")
	}
	if p.Limits.Timeout.Duration != 90*time.Second {
		t.Errorf("timeout = %v", p.Limits.Timeout.Duration)
	}
	if p.Env.Set["CI"] != "1" {
		t.Errorf("env.set = %v", p.Env.Set)
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.toml")
	os.WriteFile(path, []byte("[fs]\nraed = [\"/usr\"]\n"), 0o644)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Errorf("want unknown key error, got %v", err)
	}
}

func TestMergePrecedence(t *testing.T) {
	base, _ := Preset("standard", "/work")
	over := &Policy{}
	yes := true
	over.Net.Allow = &yes
	over.FS.Write = []string{"/extra"}
	over.Limits.MemoryMB = 128
	Merge(base, over)
	if base.Net.Allow == nil || !*base.Net.Allow {
		t.Error("overlay net did not win")
	}
	if !slices.Contains(base.FS.Write, "/extra") {
		t.Error("overlay write not appended")
	}
	if base.Limits.MemoryMB != 128 {
		t.Error("overlay limit did not win")
	}
}

func TestResolveDefaults(t *testing.T) {
	p, ok := Preset("standard", "/work")
	if !ok {
		t.Fatal("standard preset missing")
	}
	r, err := p.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if r.Net {
		t.Error("standard preset must block network")
	}
	// Write folds into read.
	if !slices.Contains(r.Read, "/work") {
		t.Errorf("write path not readable: %v", r.Read)
	}
	// Default secrets deny present.
	home, _ := os.UserHomeDir()
	if !slices.Contains(r.Deny, filepath.Join(home, ".ssh")) {
		t.Errorf("default deny missing: %v", r.Deny)
	}
}

func TestResolveNoDefaultDeny(t *testing.T) {
	p := &Policy{FS: FS{Read: []string{"/"}, NoDefaultDeny: true}}
	r, err := p.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Deny) != 0 {
		t.Errorf("deny should be empty: %v", r.Deny)
	}
}

func TestResolveRejectsRelative(t *testing.T) {
	p := &Policy{FS: FS{Read: []string{"src"}}}
	if _, err := p.Resolve(); err == nil {
		t.Error("relative path must be rejected at resolve time")
	}
}

func TestExpand(t *testing.T) {
	home, _ := os.UserHomeDir()
	got := Expand([]string{"~/x", "rel", "/abs/../abs2", ""}, "/base")
	want := []string{filepath.Join(home, "x"), "/base/rel", "/abs2"}
	if !slices.Equal(got, want) {
		t.Errorf("Expand = %v, want %v", got, want)
	}
}

func TestPresets(t *testing.T) {
	for _, name := range PresetNames() {
		p, ok := Preset(name, "/work")
		if !ok {
			t.Fatalf("preset %s missing", name)
		}
		if _, err := p.Resolve(); err != nil {
			t.Errorf("preset %s does not resolve: %v", name, err)
		}
		if PresetSummary(name) == "" {
			t.Errorf("preset %s has no summary", name)
		}
	}
	if _, ok := Preset("nope", "/work"); ok {
		t.Error("unknown preset must not resolve")
	}
}
