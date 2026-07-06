//go:build linux && !amd64 && !arm64

package nsbox

// Unsupported arch: no syscall filter (the namespaces still apply).
const auditArch = 0

func blockedSyscalls() []uint32 { return nil }
