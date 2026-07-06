package shim

import "golang.org/x/sys/unix"

// applyMemLimit uses RLIMIT_AS on macOS. There is no cgroup there, so
// this is the only knob, coarse as it is (it caps virtual address
// space, not resident memory).
func applyMemLimit(set func(int, uint64) error, memMB int) error {
	return set(unix.RLIMIT_AS, uint64(memMB)*(1<<20))
}
