//go:build !darwin && !linux

package shim

func runExec(args []string) {
	die(125, "exec shim is unix-only")
}
