package nsbox

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// A classic BPF seccomp filter. The kernel runs it against every
// syscall the child makes; we allow by default and return EPERM for a
// short list that has no place in a sandboxed workload but widens the
// attack surface (module loading, ptrace, bpf, kexec, and friends).
//
// This is defence in depth on top of the namespaces, not the main wall.
// It is installed after the mounts are built and just before exec.

type sockFilter struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

type sockFprog struct {
	length uint16
	filter *sockFilter
}

const (
	bpfLD  = 0x00
	bpfW   = 0x00
	bpfABS = 0x20
	bpfJMP = 0x05
	bpfJEQ = 0x10
	bpfRET = 0x06
	bpfK   = 0x00

	seccompRetAllow = 0x7fff0000
	seccompRetErrno = 0x00050000 // low 16 bits carry the errno

	offsetNR   = 0 // offsetof(struct seccomp_data, nr)
	offsetArch = 4 // offsetof(struct seccomp_data, arch)
)

// installSeccomp loads the filter. blockedSyscalls and auditArch are
// per-arch (seccomp_nr_*.go).
func installSeccomp() error {
	nrs := blockedSyscalls()
	if len(nrs) == 0 {
		return nil
	}
	// Layout (instruction indices in comments):
	//   0 load arch
	//   1 if arch == native, jump over the guard; else
	//   2 allow (unexpected arch: namespaces still apply)
	//   3 load nr
	//   4..4+n-1 one JEQ per blocked nr, matching -> errno return
	//   4+n allow
	//   4+n+1 errno
	filter := []sockFilter{
		{bpfLD | bpfW | bpfABS, 0, 0, offsetArch},
		{bpfJMP | bpfJEQ | bpfK, 1, 0, auditArch},
		{bpfRET | bpfK, 0, 0, seccompRetAllow},
		{bpfLD | bpfW | bpfABS, 0, 0, offsetNR},
	}
	n := len(nrs)
	for i, nr := range nrs {
		// Distance from this compare to the errno return at the end.
		jt := uint8(n - i)
		filter = append(filter, sockFilter{bpfJMP | bpfJEQ | bpfK, jt, 0, nr})
	}
	filter = append(filter,
		sockFilter{bpfRET | bpfK, 0, 0, seccompRetAllow},
		sockFilter{bpfRET | bpfK, 0, 0, seccompRetErrno | uint32(unix.EPERM)},
	)

	if _, _, errno := unix.Syscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno != 0 {
		return errno
	}
	prog := sockFprog{length: uint16(len(filter)), filter: &filter[0]}
	_, _, errno := unix.Syscall(unix.SYS_PRCTL,
		unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER,
		uintptr(unsafe.Pointer(&prog)))
	if errno != 0 {
		return errno
	}
	return nil
}
