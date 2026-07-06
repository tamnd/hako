package session

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tamnd/hako/pkg/policy"
	"github.com/tamnd/hako/pkg/shim"
)

func TestMain(m *testing.M) {
	shim.Init()
	os.Exit(m.Run())
}

func testServer(t *testing.T, dir string) (*Server, string) {
	t.Helper()
	p := &policy.Policy{FS: policy.FS{Read: []string{"/"}, Write: []string{dir}}}
	r, err := p.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "s.sock")
	srv, err := Listen(sock, r, dir)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(context.Background())
	return srv, sock
}

func sandboxWorks(t *testing.T, sock string) {
	t.Helper()
	var out bytes.Buffer
	code, err := Exec(sock, []string{"true"}, "", &out, &out)
	if err != nil || code != 0 {
		t.Skipf("sandbox unavailable here (err=%v code=%d out=%q)", err, code, out.String())
	}
}

func TestExecStreamsAndExit(t *testing.T) {
	dir := t.TempDir()
	srv, sock := testServer(t, dir)
	defer srv.Close()
	sandboxWorks(t, sock)

	var out, errBuf bytes.Buffer
	code, err := Exec(sock, []string{"sh", "-c", "echo out; echo err 1>&2; exit 7"}, "/", &out, &errBuf)
	if err != nil {
		t.Fatal(err)
	}
	if code != 7 {
		t.Errorf("exit code = %d, want 7", code)
	}
	if got := out.String(); got != "out\n" {
		t.Errorf("stdout = %q, want %q", got, "out\n")
	}
	if got := errBuf.String(); got != "err\n" {
		t.Errorf("stderr = %q, want %q", got, "err\n")
	}
}

func TestStatePersistsAcrossCommands(t *testing.T) {
	dir := t.TempDir()
	srv, sock := testServer(t, dir)
	defer srv.Close()
	sandboxWorks(t, sock)

	// One command writes a file; the next reads it back. Same box.
	var out bytes.Buffer
	if _, err := Exec(sock, []string{"sh", "-c", "echo hi > " + filepath.Join(dir, "shared")}, "/", &out, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	code, err := Exec(sock, []string{"cat", filepath.Join(dir, "shared")}, "/", &out, &out)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 || out.String() != "hi\n" {
		t.Errorf("second command did not see the first's write: code=%d out=%q", code, out.String())
	}
}

func TestStopEndsServe(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(t.TempDir(), "s.sock")
	p := &policy.Policy{FS: policy.FS{Read: []string{"/"}}}
	r, _ := p.Resolve()
	srv, err := Listen(sock, r, dir)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(context.Background()) }()

	if err := Stop(sock); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned %v, want nil after stop", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("Serve did not return after stop")
	}
	srv.Close()
}
