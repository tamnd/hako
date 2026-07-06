// Package seatbelt generates macOS sandbox profiles (SBPL) from a
// resolved policy. The profile is fed to /usr/bin/sandbox-exec. SBPL is
// last-match-wins, so allows come first and denies last.
package seatbelt

import (
	"fmt"
	"strings"

	"github.com/tamnd/hako/pkg/policy"
)

// Profile renders the SBPL text for a resolved policy. shimExe, when
// non-empty, is the hako binary itself; it gets read+exec access so the
// rlimit shim can run inside the sandbox.
func Profile(r *policy.Resolved, shimExe string) (string, error) {
	var b strings.Builder

	w := func(format string, args ...any) {
		fmt.Fprintf(&b, format+"\n", args...)
	}

	quoteAll := func(paths []string, form string) (string, error) {
		var sb strings.Builder
		for _, p := range paths {
			q, err := quote(p)
			if err != nil {
				return "", err
			}
			fmt.Fprintf(&sb, " (%s %s)", form, q)
		}
		return sb.String(), nil
	}

	w("(version 1)")
	w("(deny default)")
	w("")
	// Baseline so real programs can run at all: fork/exec plumbing,
	// sysctls the runtime reads, mach services libSystem talks to.
	w("(allow process-fork)")
	w("(allow process-info*)")
	w("(allow signal (target same-sandbox))")
	w("(allow sysctl-read)")
	w("(allow mach-lookup)")
	w("(allow file-read-metadata)")
	w("")
	// Devices and system read set every process needs.
	w(`(allow file-ioctl (literal "/dev/tty") (literal "/dev/dtracehelper") (regex #"^/dev/ttys[0-9]+$"))`)
	w(`(allow file-read* file-write-data (literal "/dev/null") (literal "/dev/zero") (literal "/dev/dtracehelper"))`)
	w(`(allow file-read* (literal "/dev/urandom") (literal "/dev/random") (literal "/dev/autofs_nowait"))`)
	w(`(allow file-read* file-write* (literal "/dev/tty") (regex #"^/dev/ttys[0-9]+$") (regex #"^/dev/fd/"))`)
	sys := []string{
		"/usr/lib", "/usr/share", "/usr/libexec",
		"/System", "/Library",
		"/private/var/db/dyld", "/private/var/db/timezone",
		"/private/etc",
	}
	sysAllows, err := quoteAll(sys, "subpath")
	if err != nil {
		return "", err
	}
	w("(allow file-read*%s)", sysAllows)
	w("")
	// Policy filesystem allows. Exec is allowed wherever read is.
	if len(r.Read) > 0 {
		reads, err := quoteAll(r.Read, "subpath")
		if err != nil {
			return "", err
		}
		w("(allow file-read*%s)", reads)
		w("(allow process-exec*%s)", reads)
	}
	if shimExe != "" {
		q, err := quote(shimExe)
		if err != nil {
			return "", err
		}
		w("(allow file-read* (literal %s))", q)
		w("(allow process-exec* (literal %s))", q)
	}
	if len(r.Write) > 0 {
		writes, err := quoteAll(r.Write, "subpath")
		if err != nil {
			return "", err
		}
		w("(allow file-read* file-write*%s)", writes)
	}
	w("")
	switch {
	case len(r.Hosts) > 0:
		// Mediated network: the child may only reach loopback, where the
		// parent's allowlisting proxy listens. Everything else is denied,
		// so a compromised child cannot dial arbitrary hosts directly.
		w("(allow network-outbound (remote ip \"localhost:*\"))")
		w("(allow network-bind (local ip \"localhost:*\"))")
		w("(deny network-outbound)")
	case r.Net:
		w("(allow network*)")
	default:
		w("(deny network*)")
	}
	// Denies last: SBPL last match wins, so these beat every allow
	// above, including user write paths.
	if len(r.Deny) > 0 {
		denies, err := quoteAll(r.Deny, "subpath")
		if err != nil {
			return "", err
		}
		w("(deny file-read* file-write*%s)", denies)
	}
	return b.String(), nil
}

// quote renders an SBPL string literal. Control characters are refused
// outright so a hostile path can never inject profile syntax.
func quote(s string) (string, error) {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("path %q contains a control character", s)
		}
	}
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`, nil
}
