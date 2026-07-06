package nsbox

import (
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/tamnd/hako/pkg/policy"
)

// Cgroup is a transient cgroup v2 group the child is placed into. It is
// best effort: unprivileged users only get one when their session has a
// delegated, writable subtree (typical under a systemd user session,
// often absent for a bare root shell). A zero Cgroup does nothing.
type Cgroup struct {
	path string
	fd   int
}

// PrepareCgroup creates a scoped cgroup with the policy's limits applied
// and returns a directory fd to hand to clone3 via UseCgroupFD. It
// returns a zero Cgroup (fd -1) when cgroup v2 is not usable here, which
// is not an error: rlimits still apply.
func PrepareCgroup(l policy.Limits) (*Cgroup, error) {
	empty := &Cgroup{fd: -1}
	if l.MemoryMB == 0 && l.Processes == 0 && l.CPUSeconds == 0 {
		return empty, nil
	}
	leaf := "hako." + strconv.Itoa(os.Getpid())
	// Try the unified root first (works when we are real root and the
	// root cgroup delegates the controllers, which is the common case),
	// then our own cgroup (works under systemd session delegation).
	for _, parent := range candidateParents() {
		enableControllers(parent)
		dir := filepath.Join(parent, leaf)
		if err := os.Mkdir(dir, 0o755); err != nil {
			continue
		}
		// The controller is only really usable if its interface file
		// showed up in the new group. Otherwise this is theatre.
		if l.MemoryMB > 0 {
			if _, err := os.Stat(filepath.Join(dir, "memory.max")); err != nil {
				os.Remove(dir)
				continue
			}
			writeCg(dir, "memory.max", strconv.Itoa(l.MemoryMB*1<<20))
			writeCg(dir, "memory.swap.max", "0")
		}
		if l.Processes > 0 {
			writeCg(dir, "pids.max", strconv.Itoa(l.Processes))
		}
		if l.CPUSeconds > 0 {
			// The hard time ceiling is the wall timeout; cpu.max just
			// makes cgroup CPU accounting present at one core's worth.
			writeCg(dir, "cpu.max", "100000 100000")
		}
		fd, err := unix.Open(dir, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			os.Remove(dir)
			continue
		}
		return &Cgroup{path: dir, fd: fd}, nil
	}
	return empty, nil
}

func candidateParents() []string {
	var out []string
	const root = "/sys/fs/cgroup"
	if st, err := os.Stat(filepath.Join(root, "cgroup.subtree_control")); err == nil && st.Mode().IsRegular() {
		out = append(out, root)
	}
	if own := ownCgroup(); own != "" && own != root {
		out = append(out, own)
	}
	return out
}

// FD is the directory fd for clone3, or -1 when there is no cgroup.
func (c *Cgroup) FD() int { return c.fd }

// Cleanup closes the fd and removes the transient group.
func (c *Cgroup) Cleanup() {
	if c == nil {
		return
	}
	if c.fd >= 0 {
		unix.Close(c.fd)
	}
	if c.path != "" {
		os.Remove(c.path)
	}
}

// ownCgroup reads the calling process's cgroup v2 path under the
// unified mount.
func ownCgroup() string {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	// Format: "0::/user.slice/...". Only the v2 line (hierarchy 0).
	for _, line := range splitLines(b) {
		if len(line) > 3 && line[0] == '0' && line[1] == ':' && line[2] == ':' {
			rel := line[3:]
			p := filepath.Join("/sys/fs/cgroup", rel)
			if st, err := os.Stat(p); err == nil && st.IsDir() {
				return p
			}
		}
	}
	return ""
}

// enableControllers asks the parent to delegate the controllers we set.
// Failures are ignored; the writes below simply become no-ops then.
func enableControllers(parent string) {
	for _, c := range []string{"+memory", "+pids", "+cpu"} {
		writeCg(parent, "cgroup.subtree_control", c)
	}
}

func writeCg(dir, name, val string) {
	_ = os.WriteFile(filepath.Join(dir, name), []byte(val), 0o644)
}

func splitLines(b []byte) []string {
	var out []string
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, string(b[start:i]))
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, string(b[start:]))
	}
	return out
}
