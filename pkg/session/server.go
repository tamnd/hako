package session

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync"

	"github.com/tamnd/hako/pkg/policy"
	"github.com/tamnd/hako/pkg/sandbox"
)

// Server holds a resolved policy and a default working directory, and
// runs each incoming command through sandbox.Run. All commands share the
// same policy and workdir, so on-disk state carries across them.
type Server struct {
	policy *policy.Resolved
	dir    string
	ln     net.Listener
	socket string
}

// Listen binds a session server to a unix socket at path. Caller runs
// Serve, then Close.
func Listen(path string, r *policy.Resolved, dir string) (*Server, error) {
	// A stale socket from a crashed server would block bind; clear it.
	if err := removeStaleSocket(path); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return &Server{policy: r, dir: dir, ln: ln, socket: path}, nil
}

// Socket is the path the server listens on.
func (s *Server) Socket() string { return s.socket }

// Serve accepts connections until a client sends stop or Close is
// called. It returns nil on a clean stop.
func (s *Server) Serve(ctx context.Context) error {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		stop := s.handle(ctx, conn)
		conn.Close()
		if stop {
			return nil
		}
	}
}

// Close releases the listener and removes the socket.
func (s *Server) Close() error {
	err := s.ln.Close()
	os.Remove(s.socket)
	return err
}

// handle serves one connection: read the request, run it, stream output.
// It returns true when the request asked the server to stop.
func (s *Server) handle(ctx context.Context, conn net.Conn) bool {
	typ, payload, err := readFrame(conn)
	if err != nil || typ != frameRequest {
		return false
	}
	var req request
	if err := json.Unmarshal(payload, &req); err != nil {
		writeFrame(conn, frameError, []byte("bad request: "+err.Error()))
		return false
	}
	if req.Stop {
		writeExit(conn, 0)
		return true
	}
	if len(req.Argv) == 0 {
		writeFrame(conn, frameError, []byte("empty argv"))
		return false
	}
	dir := s.dir
	if req.Dir != "" {
		dir = req.Dir
	}

	// One mutex guards the shared conn so stdout and stderr frames never
	// interleave mid-frame.
	var mu sync.Mutex
	res, err := sandbox.Run(ctx, s.policy, sandbox.Command{
		Argv:   req.Argv,
		Dir:    dir,
		Stdout: &frameWriter{conn: conn, typ: frameStdout, mu: &mu},
		Stderr: &frameWriter{conn: conn, typ: frameStderr, mu: &mu},
	})
	if err != nil {
		mu.Lock()
		writeFrame(conn, frameError, []byte(err.Error()))
		mu.Unlock()
		return false
	}
	mu.Lock()
	writeExit(conn, res.ExitCode)
	mu.Unlock()
	return false
}

func writeExit(conn net.Conn, code int) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(int32(code)))
	writeFrame(conn, frameExit, b[:])
}

// frameWriter turns Write calls into stdout/stderr frames on the shared
// connection.
type frameWriter struct {
	conn io.Writer
	typ  byte
	mu   *sync.Mutex
}

func (w *frameWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	// Split oversized writes across frames.
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxFrame {
			chunk = chunk[:maxFrame]
		}
		if err := writeFrame(w.conn, w.typ, chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func removeStaleSocket(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil // nothing there
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return errors.New("session: refusing to reuse non-socket path " + path)
	}
	// If something is still listening, bind will fail later and tell the
	// user; we only clear a dead socket file.
	if c, err := net.Dial("unix", path); err == nil {
		c.Close()
		return errors.New("session: a server is already listening on " + path)
	}
	return os.Remove(path)
}
