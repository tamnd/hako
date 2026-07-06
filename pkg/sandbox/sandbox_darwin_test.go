package sandbox

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tamnd/hako/pkg/policy"
	"github.com/tamnd/hako/pkg/shim"
)

// The rlimit shim re-execs this very binary, so the test binary must
// dispatch it exactly like an embedder's main would.
func TestMain(m *testing.M) {
	shim.Init()
	os.Exit(m.Run())
}

// These tests run real commands under sandbox-exec. They need a stock
// macOS; skip automatically when sandbox-exec cannot apply a profile
// (some CI sandboxes forbid nesting).
func sandboxWorks(t *testing.T) {
	t.Helper()
	r := testPolicy(t, nil, nil)
	res, err := Run(context.Background(), r, Command{Argv: []string{"/usr/bin/true"}})
	if err != nil || res.ExitCode != 0 {
		t.Skipf("sandbox-exec unavailable here (err=%v code=%d)", err, res.ExitCode)
	}
}

func testPolicy(t *testing.T, write, deny []string) *policy.Resolved {
	t.Helper()
	p := &policy.Policy{
		FS: policy.FS{Read: []string{"/"}, Write: write, Deny: deny},
	}
	r, err := p.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func runCmd(t *testing.T, r *policy.Resolved, argv ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	res, err := Run(context.Background(), r, Command{
		Argv:   argv,
		Stdout: &out,
		Stderr: &out,
	})
	if err != nil {
		t.Fatalf("Run(%v): %v", argv, err)
	}
	return res.ExitCode, out.String()
}

func TestRunEcho(t *testing.T) {
	sandboxWorks(t)
	code, out := runCmd(t, testPolicy(t, nil, nil), "/bin/echo", "hello")
	if code != 0 || strings.TrimSpace(out) != "hello" {
		t.Errorf("code=%d out=%q", code, out)
	}
}

func TestWriteAllowedAndBlocked(t *testing.T) {
	sandboxWorks(t)
	allowed := t.TempDir()
	blocked := t.TempDir()
	r := testPolicy(t, []string{allowed}, nil)

	code, out := runCmd(t, r, "/usr/bin/touch", filepath.Join(allowed, "ok"))
	if code != 0 {
		t.Errorf("write inside allowlist failed: code=%d out=%q", code, out)
	}
	code, _ = runCmd(t, r, "/usr/bin/touch", filepath.Join(blocked, "nope"))
	if code == 0 {
		t.Error("write outside allowlist must fail")
	}
}

func TestDenyBeatsRead(t *testing.T) {
	sandboxWorks(t)
	secret := t.TempDir()
	path := filepath.Join(secret, "token")
	if err := os.WriteFile(path, []byte("s3cret"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := testPolicy(t, nil, []string{secret})
	code, out := runCmd(t, r, "/bin/cat", path)
	if code == 0 {
		t.Errorf("deny path was readable: %q", out)
	}
}

func TestNetworkBlocked(t *testing.T) {
	sandboxWorks(t)
	r := testPolicy(t, nil, nil)
	// nc to localhost fails fast when the sandbox denies socket use.
	code, _ := runCmd(t, r, "/usr/bin/nc", "-z", "-w", "1", "127.0.0.1", "80")
	if code == 0 {
		t.Error("network must be blocked by default")
	}
}

func TestTimeout(t *testing.T) {
	sandboxWorks(t)
	r := testPolicy(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	res, err := Run(ctx, r, Command{Argv: []string{"/bin/sleep", "10"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut || res.ExitCode != ExitTimeout {
		t.Errorf("want timeout 124, got %+v", res)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("timeout did not kill the process group promptly")
	}
}

func TestRlimitShim(t *testing.T) {
	sandboxWorks(t)
	dir := t.TempDir()
	p := &policy.Policy{
		FS:     policy.FS{Read: []string{"/"}, Write: []string{dir}},
		Limits: policy.Limits{FileSizeMB: 1},
	}
	r, err := p.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	// dd past the 1MB fsize rlimit must fail; under it must pass.
	code, out := runCmd(t, r, "/bin/dd", "if=/dev/zero",
		"of="+filepath.Join(dir, "big"), "bs=1m", "count=4")
	if code == 0 {
		t.Errorf("fsize rlimit not applied: %s", out)
	}
	code, out = runCmd(t, r, "/bin/dd", "if=/dev/zero",
		"of="+filepath.Join(dir, "small"), "bs=64k", "count=1")
	if code != 0 {
		t.Errorf("small write under rlimit failed: %s", out)
	}
}

func TestEnvScrubbed(t *testing.T) {
	sandboxWorks(t)
	t.Setenv("HAKO_SECRET_TOKEN", "leak-me")
	r := testPolicy(t, nil, nil)
	code, out := runCmd(t, r, "/usr/bin/env")
	if code != 0 {
		t.Fatalf("env failed: %s", out)
	}
	if strings.Contains(out, "HAKO_SECRET_TOKEN") {
		t.Error("unlisted env var crossed into the sandbox")
	}
	if !strings.Contains(out, "PATH=") {
		t.Error("PATH should pass through by default")
	}
}
