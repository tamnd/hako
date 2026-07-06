package shim

// applyMemLimit is a no-op on Linux: memory is capped with cgroup v2
// memory.max, set up by the parent. RLIMIT_AS is deliberately avoided,
// because it caps virtual address space and breaks runtimes (Go, the
// JVM, anything with large mmap reservations), including hako's own init
// process, which stays alive to reap the child.
func applyMemLimit(set func(int, uint64) error, memMB int) error {
	return nil
}
