package seatbelt

import (
	"strings"
	"testing"

	"github.com/tamnd/hako/pkg/policy"
)

func resolved(t *testing.T, p *policy.Policy) *policy.Resolved {
	t.Helper()
	r, err := p.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestProfileShape(t *testing.T) {
	yes := true
	r := resolved(t, &policy.Policy{
		FS: policy.FS{
			Read:  []string{"/data"},
			Write: []string{"/data/out"},
			Deny:  []string{"/data/secret"},
		},
		Net: policy.Net{Allow: &yes},
	})
	p, err := Profile(r, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"(version 1)",
		"(deny default)",
		`(allow file-read* (subpath "/data")`,
		`(allow file-read* file-write* (subpath "/data/out")`,
		"(allow network*)",
		`(deny file-read* file-write* (subpath "/data/secret")`,
		"(allow process-fork)",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("profile missing %q\n%s", want, p)
		}
	}
	// Denies must come after allows: SBPL is last-match-wins.
	if strings.Index(p, `(deny file-read* file-write*`) < strings.Index(p, `(allow file-read* file-write*`) {
		t.Error("denies must be emitted after allows")
	}
}

func TestProfileNoNet(t *testing.T) {
	r := resolved(t, &policy.Policy{FS: policy.FS{Read: []string{"/"}}})
	p, err := Profile(r, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p, "(allow network*)") {
		t.Error("network must not be allowed")
	}
	if !strings.Contains(p, "(deny network*)") {
		t.Error("explicit network deny missing")
	}
}

func TestProfileShim(t *testing.T) {
	r := resolved(t, &policy.Policy{FS: policy.FS{Read: []string{"/tmp"}}})
	p, err := Profile(r, "/usr/local/bin/hako")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p, `(allow process-exec* (literal "/usr/local/bin/hako"))`) {
		t.Error("shim exec allow missing")
	}
}

func TestQuoteEscapes(t *testing.T) {
	q, err := quote(`/pa"th/wi\th`)
	if err != nil {
		t.Fatal(err)
	}
	if q != `"/pa\"th/wi\\th"` {
		t.Errorf("quote = %s", q)
	}
	if _, err := quote("/evil\npath"); err == nil {
		t.Error("control characters must be refused")
	}
}
