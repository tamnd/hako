package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestLoggerWritesJSONL(t *testing.T) {
	var buf bytes.Buffer
	l := NewWriter(&buf)
	l.Log("run.start", map[string]any{"argv": []string{"echo", "hi"}})
	l.Log("net.deny", map[string]any{"host": "evil.com:443"})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d: %q", len(lines), buf.String())
	}
	var first Event
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("line 0 is not JSON: %v", err)
	}
	if first.Kind != "run.start" || first.Time == "" {
		t.Errorf("unexpected first event: %+v", first)
	}
	var second Event
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("line 1 is not JSON: %v", err)
	}
	if second.Fields["host"] != "evil.com:443" {
		t.Errorf("host field lost: %+v", second.Fields)
	}
}

func TestNilLoggerIsNoop(t *testing.T) {
	var l *Logger
	l.Log("run.start", nil) // must not panic
	if err := l.Close(); err != nil {
		t.Errorf("nil Close: %v", err)
	}
}
