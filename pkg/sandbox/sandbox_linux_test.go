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

// The init stage re-execs this very binary, so the test binary must
// dispatch it exactly like an embedder's main would.
func TestMain(m *testing.M) {
	shim.Init()
	os.Exit(m.Run())
}

// sandboxWorks skips when user namespaces are unavailable (locked-down
// kernels, restrictive AppArmor, some CI containers).
func sandboxWorks(t *testing.T) {
	t.Helper()
	r := testPolicy(t, nil, nil)
	res, err := Run(context.Background(), r, Command{Argv: []string{"true"}})
	if err != nil || res.ExitCode != 0 {
		t.Skipf("user namespaces unavailable here (err=%v code=%d)", err, res.ExitCode)
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
		Dir:    "/",
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
	code, out := runCmd(t, testPolicy(t, nil, nil), "echo", "hello")
	if code != 0 || strings.TrimSpace(out) != "hello" {
		t.Errorf("code=%d out=%q", code, out)
	}
}

func TestWriteAllowedAndBlocked(t *testing.T) {
	sandboxWorks(t)
	allowed := t.TempDir()
	r := testPolicy(t, []string{allowed}, nil)

	code, out := runCmd(t, r, "touch", filepath.Join(allowed, "ok"))
	if code != 0 {
		t.Errorf("write inside allowlist failed: code=%d out=%q", code, out)
	}
	if _, err := os.Stat(filepath.Join(allowed, "ok")); err != nil {
		t.Error("allowed write did not reach the host")
	}
	code, _ = runCmd(t, r, "sh", "-c", "echo x > /etc/hako-escape")
	if code == 0 {
		t.Error("write outside allowlist must fail")
	}
	if _, err := os.Stat("/etc/hako-escape"); err == nil {
		os.Remove("/etc/hako-escape")
		t.Fatal("sandbox wrote to the host /etc")
	}
}

func TestDenyHidesContent(t *testing.T) {
	sandboxWorks(t)
	secret := t.TempDir()
	path := filepath.Join(secret, "token")
	if err := os.WriteFile(path, []byte("s3cret"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := testPolicy(t, nil, []string{secret})
	code, out := runCmd(t, r, "cat", path)
	if code == 0 && strings.Contains(out, "s3cret") {
		t.Errorf("deny path content leaked: %q", out)
	}
}

func TestNetworkBlockedButLoopbackUp(t *testing.T) {
	sandboxWorks(t)
	r := testPolicy(t, nil, nil)
	// In the fresh netns there is no route to anywhere...
	code, _ := runCmd(t, r, "bash", "-c",
		"exec 3<>/dev/tcp/1.1.1.1/80")
	if code == 0 {
		t.Error("outbound network must be blocked")
	}
	// ...but lo must be up for localhost-only tools.
	code, out := runCmd(t, r, "sh", "-c",
		"cat /sys/class/net/lo/operstate 2>/dev/null || ip link show lo")
	if code != 0 || !(strings.Contains(out, "up") || strings.Contains(out, "UP") || strings.Contains(out, "unknown")) {
		t.Errorf("loopback not up: code=%d out=%q", code, out)
	}
}

func TestPid1Reaper(t *testing.T) {
	sandboxWorks(t)
	r := testPolicy(t, nil, nil)
	// The target must not be pid 1: init stays around to reap.
	code, out := runCmd(t, r, "sh", "-c", "echo $$")
	if code != 0 {
		t.Fatalf("code=%d out=%q", code, out)
	}
	if strings.TrimSpace(out) == "1" {
		t.Error("target ran as pid 1; the reaper is missing")
	}
	// Exit codes still pass through the reaper.
	code, _ = runCmd(t, r, "sh", "-c", "exit 42")
	if code != 42 {
		t.Errorf("exit code through reaper = %d, want 42", code)
	}
}

func TestTimeout(t *testing.T) {
	sandboxWorks(t)
	r := testPolicy(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	res, err := Run(ctx, r, Command{Argv: []string{"sleep", "10"}, Dir: "/"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut || res.ExitCode != ExitTimeout {
		t.Errorf("want timeout 124, got %+v", res)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("timeout did not kill the namespace promptly")
	}
}

func TestRlimitFsize(t *testing.T) {
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
	code, out := runCmd(t, r, "dd", "if=/dev/zero",
		"of="+filepath.Join(dir, "big"), "bs=1M", "count=4")
	if code == 0 {
		t.Errorf("fsize rlimit not applied: %s", out)
	}
}

func TestEnvScrubbed(t *testing.T) {
	sandboxWorks(t)
	t.Setenv("HAKO_SECRET_TOKEN", "leak-me")
	r := testPolicy(t, nil, nil)
	code, out := runCmd(t, r, "env")
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

func TestSeccompActive(t *testing.T) {
	sandboxWorks(t)
	r := testPolicy(t, nil, nil)
	// The kernel reports filter mode (2) in /proc/self/status once a
	// seccomp BPF program is installed.
	code, out := runCmd(t, r, "grep", "Seccomp:", "/proc/self/status")
	if code != 0 {
		t.Skipf("cannot read seccomp status: %s", out)
	}
	if !strings.Contains(out, "2") {
		t.Errorf("seccomp filter not active: %q", strings.TrimSpace(out))
	}
}

func TestLimitsDoNotCrashInit(t *testing.T) {
	sandboxWorks(t)
	// Regression: applying a memory limit once made the reaper's Go
	// init crash under RLIMIT_AS. Setting every limit must still run.
	p := &policy.Policy{
		FS: policy.FS{Read: []string{"/"}},
		Limits: policy.Limits{
			MemoryMB: 128, CPUSeconds: 30, Processes: 64,
			OpenFiles: 256, FileSizeMB: 8,
		},
	}
	r, err := p.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	code, out := runCmd(t, r, "echo", "alive")
	if code != 0 || strings.TrimSpace(out) != "alive" {
		t.Errorf("limited run failed: code=%d out=%q", code, out)
	}
}

func TestHostnameIsolated(t *testing.T) {
	sandboxWorks(t)
	r := testPolicy(t, nil, nil)
	code, out := runCmd(t, r, "hostname")
	if code != 0 || strings.TrimSpace(out) != "hako" {
		t.Errorf("hostname = %q, want hako", strings.TrimSpace(out))
	}
}
