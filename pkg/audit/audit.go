// Package audit writes a JSON Lines record of what a sandboxed run did:
// the policy it ran under, and every access the sandbox refused. It is
// deliberately simple, one object per line, so the log is easy to grep,
// tail, or feed to jq.
package audit

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Event is one line in the audit log. Fields carries kind-specific data.
type Event struct {
	Time   string         `json:"time"`
	Kind   string         `json:"kind"`
	Fields map[string]any `json:"fields,omitempty"`
}

// Logger appends events to a writer, one JSON object per line. A nil
// Logger is a valid no-op, so callers never need to nil-check.
type Logger struct {
	mu     sync.Mutex
	w      io.Writer
	closer io.Closer
	now    func() time.Time
}

// Open creates a Logger appending to the file at path, creating it if
// needed. The caller must Close it.
func Open(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Logger{w: f, closer: f, now: time.Now}, nil
}

// NewWriter builds a Logger over an arbitrary writer, for tests or when
// the destination is not a file.
func NewWriter(w io.Writer) *Logger {
	return &Logger{w: w, now: time.Now}
}

// Log writes one event. Safe for concurrent use and safe on a nil
// Logger (does nothing).
func (l *Logger) Log(kind string, fields map[string]any) {
	if l == nil {
		return
	}
	e := Event{
		Time:   l.now().UTC().Format(time.RFC3339Nano),
		Kind:   kind,
		Fields: fields,
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')
	l.mu.Lock()
	l.w.Write(b)
	l.mu.Unlock()
}

// Close releases the underlying file, if any.
func (l *Logger) Close() error {
	if l == nil || l.closer == nil {
		return nil
	}
	return l.closer.Close()
}
