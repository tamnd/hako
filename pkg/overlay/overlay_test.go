package overlay

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMaterializeAndDiff(t *testing.T) {
	src := t.TempDir()
	write(t, src, "a.txt", "orig")
	write(t, src, "keep.txt", "keep")
	write(t, src, "sub/nested.txt", "deep")

	ov, err := Materialize(src)
	if err != nil {
		t.Fatal(err)
	}
	defer ov.Cleanup()

	// The clone must be a faithful copy to start.
	if got := read(t, ov.Dir, "a.txt"); got != "orig" {
		t.Fatalf("clone a.txt = %q", got)
	}
	if diff, _ := ov.Diff(); len(diff) != 0 {
		t.Fatalf("fresh clone should have no diff, got %v", diff)
	}

	// Edit the clone: modify, add, remove.
	write(t, ov.Dir, "a.txt", "changed")
	write(t, ov.Dir, "new.txt", "brand new")
	if err := os.Remove(filepath.Join(ov.Dir, "keep.txt")); err != nil {
		t.Fatal(err)
	}

	changes, err := ov.Diff()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]ChangeKind{}
	for _, c := range changes {
		got[c.Path] = c.Kind
	}
	want := map[string]ChangeKind{
		"a.txt":    Modified,
		"new.txt":  Added,
		"keep.txt": Removed,
	}
	for path, kind := range want {
		if got[path] != kind {
			t.Errorf("%s: got %q, want %q", path, got[path], kind)
		}
	}
	if len(changes) != len(want) {
		t.Errorf("changes = %v, want exactly %d", changes, len(want))
	}

	// The original must be untouched.
	if read(t, src, "a.txt") != "orig" {
		t.Error("overlay leaked writes into the original")
	}
	if _, err := os.Stat(filepath.Join(src, "keep.txt")); err != nil {
		t.Error("overlay deleted from the original")
	}
}

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
