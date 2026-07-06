package session

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
)

// Exec sends a command to the session server at socket and streams its
// output to stdout and stderr. It returns the command's exit code.
func Exec(socket string, argv []string, dir string, stdout, stderr io.Writer) (int, error) {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return -1, fmt.Errorf("session: connect %s: %w", socket, err)
	}
	defer conn.Close()

	req, _ := json.Marshal(request{Argv: argv, Dir: dir})
	if err := writeFrame(conn, frameRequest, req); err != nil {
		return -1, err
	}
	return pump(conn, stdout, stderr)
}

// Stop tells the server to shut down.
func Stop(socket string) error {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return fmt.Errorf("session: connect %s: %w", socket, err)
	}
	defer conn.Close()
	req, _ := json.Marshal(request{Stop: true})
	if err := writeFrame(conn, frameRequest, req); err != nil {
		return err
	}
	_, err = pump(conn, io.Discard, io.Discard)
	return err
}

// pump reads frames until an exit frame arrives, writing output as it
// goes. It returns the exit code.
func pump(conn net.Conn, stdout, stderr io.Writer) (int, error) {
	for {
		typ, payload, err := readFrame(conn)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return -1, errors.New("session: server closed without an exit code")
			}
			return -1, err
		}
		switch typ {
		case frameStdout:
			stdout.Write(payload)
		case frameStderr:
			stderr.Write(payload)
		case frameError:
			return -1, errors.New(string(payload))
		case frameExit:
			if len(payload) != 4 {
				return -1, errors.New("session: malformed exit frame")
			}
			return int(int32(binary.BigEndian.Uint32(payload))), nil
		}
	}
}
