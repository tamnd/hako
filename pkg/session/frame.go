// Package session keeps one sandbox warm and runs many commands through
// it over a unix socket. `hako session start` serves; `hako session exec`
// sends a command and streams its output back; `hako session stop` shuts
// it down. Every command shares the same resolved policy and the same
// working area, so writes from one command are visible to the next,
// which is what makes an overlay session useful.
package session

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Frame types on the wire. Each frame is: 1 byte type, 4 byte big-endian
// length, then that many payload bytes.
const (
	frameRequest = 1 // client -> server: JSON request
	frameStdout  = 2 // server -> client: stdout bytes
	frameStderr  = 3 // server -> client: stderr bytes
	frameExit    = 4 // server -> client: 4 byte exit code
	frameError   = 5 // server -> client: setup error string
)

const maxFrame = 1 << 20 // 1 MiB, plenty for a control message or a chunk

func writeFrame(w io.Writer, typ byte, payload []byte) error {
	if len(payload) > maxFrame {
		return fmt.Errorf("session: frame too large (%d)", len(payload))
	}
	var head [5]byte
	head[0] = typ
	binary.BigEndian.PutUint32(head[1:], uint32(len(payload)))
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readFrame(r io.Reader) (byte, []byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(head[1:])
	if n > maxFrame {
		return 0, nil, fmt.Errorf("session: frame too large (%d)", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return head[0], payload, nil
}

// request is the JSON a client sends to run a command, or to stop.
type request struct {
	Stop bool     `json:"stop,omitempty"`
	Argv []string `json:"argv,omitempty"`
	Dir  string   `json:"dir,omitempty"`
}
