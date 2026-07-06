// Package overlay gives a sandboxed command a copy-on-write view of a
// directory: it clones the tree cheaply, lets the command write into the
// clone, and then reports what changed. The point is review. An agent
// edits files, and you see a diff before anything touches the original.
package overlay

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Overlay is a writable clone of a source directory.
type Overlay struct {
	Src string // the original directory
	Dir string // the writable clone the command runs in
}

// Materialize clones src into a fresh temp directory. On macOS the clone
// is copy-on-write (APFS clonefile), so it is near-instant and shares
// storage until the command writes; elsewhere it is a plain recursive
// copy.
func Materialize(src string) (*Overlay, error) {
	src, err := filepath.Abs(src)
	if err != nil {
		return nil, err
	}
	if fi, err := os.Stat(src); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("overlay: %s is not a directory", src)
	}
	parent, err := os.MkdirTemp("", "hako-overlay-")
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(parent, filepath.Base(src))
	if err := cloneTree(src, dir); err != nil {
		os.RemoveAll(parent)
		return nil, err
	}
	return &Overlay{Src: src, Dir: dir}, nil
}

// Cleanup removes the clone. Call it once you have reviewed or applied
// the diff.
func (o *Overlay) Cleanup() error {
	if o == nil || o.Dir == "" {
		return nil
	}
	return os.RemoveAll(filepath.Dir(o.Dir))
}

// ChangeKind is how a path differs between the source and the clone.
type ChangeKind string

const (
	Added    ChangeKind = "added"
	Modified ChangeKind = "modified"
	Removed  ChangeKind = "removed"
)

// Change is one entry in the review diff. Path is relative to the tree
// root.
type Change struct {
	Path string
	Kind ChangeKind
}

// Diff compares the clone against the original and returns what the
// command changed, sorted by path. It uses size and modification time,
// which is enough to spot edits: a copy-on-write clone shares mtime with
// the source until a file is rewritten.
func (o *Overlay) Diff() ([]Change, error) {
	orig, err := scan(o.Src)
	if err != nil {
		return nil, err
	}
	cur, err := scan(o.Dir)
	if err != nil {
		return nil, err
	}
	var out []Change
	for rel, cf := range cur {
		of, ok := orig[rel]
		if !ok {
			out = append(out, Change{rel, Added})
			continue
		}
		if cf.size != of.size || !cf.mtime.Equal(of.mtime) {
			out = append(out, Change{rel, Modified})
		}
	}
	for rel := range orig {
		if _, ok := cur[rel]; !ok {
			out = append(out, Change{rel, Removed})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

type fileMeta struct {
	size  int64
	mtime time.Time
}

// scan records size and mtime for every regular file under root, keyed
// by path relative to root.
func scan(root string) (map[string]fileMeta, error) {
	out := map[string]fileMeta{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		out[rel] = fileMeta{size: info.Size(), mtime: info.ModTime()}
		return nil
	})
	return out, err
}
