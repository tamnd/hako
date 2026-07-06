package nsbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Setup builds the sandbox root and pivots into it. It runs as pid 1 of
// the new namespaces, with full capabilities inside the user namespace.
func Setup(s *Spec) error {
	// Our mount changes must never propagate back to the host.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make / private: %w", err)
	}
	root, err := os.MkdirTemp("", "hako-root-")
	if err != nil {
		return err
	}
	if err := unix.Mount("hako", root, "tmpfs", unix.MS_NOSUID, "mode=0755"); err != nil {
		return fmt.Errorf("root tmpfs: %w", err)
	}
	for _, p := range expandRoot(s.Read, root) {
		if err := bind(root, p, true); err != nil {
			return err
		}
	}
	for _, p := range expandRoot(s.Write, root) {
		if err := bind(root, p, false); err != nil {
			return err
		}
	}
	if err := mountProc(root); err != nil {
		return err
	}
	if err := mountDev(root); err != nil {
		return err
	}
	for _, d := range s.Deny {
		if err := mask(root, d); err != nil {
			return err
		}
	}
	// If /tmp was bound, the staging root shows up inside itself;
	// detach that inner copy.
	inner := filepath.Join(root, root)
	unix.Unmount(inner, unix.MNT_DETACH)
	os.Remove(inner)

	old := filepath.Join(root, ".hako-old")
	if err := os.MkdirAll(old, 0o700); err != nil {
		return err
	}
	if err := unix.PivotRoot(root, old); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := unix.Chdir("/"); err != nil {
		return err
	}
	if err := unix.Unmount("/.hako-old", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("detach old root: %w", err)
	}
	os.Remove("/.hako-old")
	unix.Sethostname([]byte("hako"))

	dir := s.Dir
	if dir == "" {
		dir = "/"
	}
	if err := os.Chdir(dir); err != nil {
		return fmt.Errorf("chdir %s: %w", dir, err)
	}
	return nil
}

// expandRoot replaces a bare "/" with the top-level directories, since
// binding / over the staging tmpfs would make it read-only before we
// finish building it. /proc, /sys handled separately; /dev built fresh.
func expandRoot(paths []string, root string) []string {
	var out []string
	for _, p := range paths {
		if p != "/" {
			out = append(out, p)
			continue
		}
		ents, err := os.ReadDir("/")
		if err != nil {
			continue
		}
		for _, e := range ents {
			name := e.Name()
			if name == "proc" || name == "dev" || name == "lost+found" {
				continue
			}
			top := "/" + name
			if strings.HasPrefix(root, top+"/") && name != "tmp" {
				continue
			}
			out = append(out, top)
		}
	}
	return out
}

func bind(root, src string, ro bool) error {
	fi, err := os.Lstat(src)
	if err != nil {
		// Allowlisted paths that do not exist are simply skipped.
		return nil
	}
	dst := filepath.Join(root, src)
	if fi.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(src)
		if err != nil {
			return nil
		}
		os.MkdirAll(filepath.Dir(dst), 0o755)
		return os.Symlink(target, dst)
	}
	if fi.IsDir() {
		if err := os.MkdirAll(dst, 0o755); err != nil {
			return err
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(dst, os.O_CREATE, 0o644)
		if err != nil {
			return err
		}
		f.Close()
	}
	if err := unix.Mount(src, dst, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("bind %s: %w", src, err)
	}
	if ro {
		return remountRO(dst)
	}
	return nil
}

// remountRO flips a bind mount read-only. The kernel refuses a remount
// that drops locked flags inherited from the source mount, so retry
// with progressively more of them.
func remountRO(dst string) error {
	base := uintptr(unix.MS_BIND | unix.MS_REMOUNT | unix.MS_RDONLY)
	extras := []uintptr{
		0,
		unix.MS_NOSUID,
		unix.MS_NOSUID | unix.MS_NODEV,
		unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC,
		unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC | unix.MS_NOATIME,
	}
	var err error
	for _, ex := range extras {
		if err = unix.Mount("", dst, "", base|ex, ""); err == nil {
			return nil
		}
	}
	return fmt.Errorf("remount ro %s: %w", dst, err)
}

func mountProc(root string) error {
	p := filepath.Join(root, "proc")
	if err := os.MkdirAll(p, 0o755); err != nil {
		return err
	}
	err := unix.Mount("proc", p, "proc",
		unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "")
	if err != nil {
		return fmt.Errorf("mount proc: %w", err)
	}
	return nil
}

func mountDev(root string) error {
	d := filepath.Join(root, "dev")
	if err := os.MkdirAll(d, 0o755); err != nil {
		return err
	}
	if err := unix.Mount("hako-dev", d, "tmpfs", unix.MS_NOSUID, "mode=0755"); err != nil {
		return fmt.Errorf("mount dev: %w", err)
	}
	for _, name := range []string{"null", "zero", "full", "random", "urandom", "tty"} {
		src := "/dev/" + name
		dst := filepath.Join(d, name)
		f, err := os.OpenFile(dst, os.O_CREATE, 0o644)
		if err != nil {
			return err
		}
		f.Close()
		if err := unix.Mount(src, dst, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("bind %s: %w", src, err)
		}
	}
	links := map[string]string{
		"fd":     "/proc/self/fd",
		"stdin":  "/proc/self/fd/0",
		"stdout": "/proc/self/fd/1",
		"stderr": "/proc/self/fd/2",
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(d, name)); err != nil {
			return err
		}
	}
	return nil
}

// mask hides a denied path with an empty, unreadable mount.
func mask(root, p string) error {
	dst := filepath.Join(root, p)
	fi, err := os.Lstat(dst)
	if err != nil {
		return nil // nothing bound there, nothing to hide
	}
	if fi.IsDir() {
		err = unix.Mount("hako-mask", dst, "tmpfs",
			unix.MS_RDONLY|unix.MS_NOSUID, "mode=0000")
	} else {
		empty := filepath.Join(root, ".hako-empty")
		if f, ferr := os.OpenFile(empty, os.O_CREATE, 0o000); ferr == nil {
			f.Close()
		}
		err = unix.Mount(empty, dst, "", unix.MS_BIND, "")
	}
	if err != nil {
		return fmt.Errorf("mask %s: %w", p, err)
	}
	return nil
}
