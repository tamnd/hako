//go:build !linux

package shim

// runInit only exists on Linux; reaching it elsewhere is a bug.
func runInit() {
	die(125, "namespace init is linux-only")
}
