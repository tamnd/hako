//go:build linux && amd64

package nsbox

import "golang.org/x/sys/unix"

// AUDIT_ARCH_X86_64
const auditArch = 0xc000003e

func blockedSyscalls() []uint32 {
	return []uint32{
		unix.SYS_PTRACE,
		unix.SYS_BPF,
		unix.SYS_KEXEC_LOAD,
		unix.SYS_KEXEC_FILE_LOAD,
		unix.SYS_INIT_MODULE,
		unix.SYS_FINIT_MODULE,
		unix.SYS_DELETE_MODULE,
		unix.SYS_PERF_EVENT_OPEN,
		unix.SYS_USERFAULTFD,
		unix.SYS_OPEN_BY_HANDLE_AT,
		unix.SYS_KEYCTL,
		unix.SYS_ADD_KEY,
		unix.SYS_REQUEST_KEY,
	}
}
