package seatbelt

import (
	"strings"
	"testing"

	"github.com/tamnd/hako/pkg/policy"
)

// FuzzProfilePaths throws hostile paths at the generator. A path that
// survives quoting must appear only inside a balanced string literal: it
// can never introduce a new SBPL form (an unescaped paren or quote) that
// would flip a deny into an allow. Paths that cannot be represented
// safely must be refused, not silently emitted.
func FuzzProfilePaths(f *testing.F) {
	seeds := []string{
		`/data`,
		`/pa"th`,
		`/back\slash`,
		`/nested/"))(allow network*)((`,
		`/quote"and(paren)`,
		"/tab\tinside",
		"/new\nline",
		"/nul\x00byte",
		"/unicode/é世界",
		`/) (allow file-write* (subpath "/`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, path string) {
		r := &policy.Resolved{
			Name:  "fuzz",
			Read:  []string{"/base"},
			Write: []string{path},
			Deny:  []string{path},
		}
		out, err := Profile(r, path)
		if err != nil {
			// Refusing a dangerous path is a valid, safe outcome.
			return
		}
		// The generator claimed the path was safe. Every quote must open
		// and close a literal cleanly, so the attacker's bytes can never
		// escape their string. With literal contents redacted, no new
		// SBPL form (like a network allow) may appear.
		assertBalancedLiterals(t, out, path)
		if code := redactLiterals(out); strings.Contains(code, "(allow network") {
			t.Fatalf("path %q injected a network allow outside a literal:\n%s", path, out)
		}
	})
}

// redactLiterals blanks out the contents of every "..." string literal,
// leaving the SBPL structure (parens, forms) intact. If a hostile path
// stayed inside its literal, its bytes vanish here; if it broke out,
// they would remain and trip the caller's checks.
func redactLiterals(profile string) string {
	var b strings.Builder
	inStr := false
	esc := false
	for _, c := range profile {
		switch {
		case esc:
			esc = false
		case c == '\\' && inStr:
			esc = true
		case c == '"':
			inStr = !inStr
			b.WriteRune(c)
		case !inStr:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// assertBalancedLiterals walks the profile and checks that every double
// quote opens and closes a literal cleanly, treating \" and \\ as
// escapes. A hostile path that broke out of its literal would leave the
// scanner mid-string at end of line or unbalance the quotes.
func assertBalancedLiterals(t *testing.T, profile, path string) {
	t.Helper()
	for _, line := range strings.Split(profile, "\n") {
		inStr := false
		esc := false
		for _, c := range line {
			switch {
			case esc:
				esc = false
			case c == '\\' && inStr:
				esc = true
			case c == '"':
				inStr = !inStr
			}
		}
		if inStr {
			t.Fatalf("path %q left an unterminated string literal: %q", path, line)
		}
		if esc {
			t.Fatalf("path %q left a dangling escape: %q", path, line)
		}
	}
}
