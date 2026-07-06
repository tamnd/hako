// Package netproxy is a small HTTP/HTTPS forward proxy that only lets
// through connections to an allowlist of hosts. It runs in the
// unsandboxed parent; the sandboxed child is confined to loopback and
// pointed at this proxy with HTTP_PROXY/HTTPS_PROXY. That turns "no
// network" into "network, but only these hosts".
//
// It speaks just enough of the proxy protocol for real clients: the
// CONNECT method for TLS (the common case, curl/git/npm over https) and
// absolute-form GET/POST/... for plain http. Everything else is refused.
package netproxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// Proxy is a running allowlisting forward proxy. Create it with Start
// and stop it with Close.
type Proxy struct {
	allow    *allowlist
	ln       net.Listener
	dialer   net.Dialer
	wg       sync.WaitGroup
	mu       sync.Mutex
	closed   bool
	onDenied func(host string)
}

// Start binds a proxy to loopback and begins serving in the background.
// hosts is the allowlist: entries are "host" (any port) or "host:port".
// The returned Proxy's Addr is where the child should point its
// HTTP(S)_PROXY variables.
func Start(hosts []string) (*Proxy, error) {
	al, err := parseAllowlist(hosts)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("netproxy: listen: %w", err)
	}
	p := &Proxy{
		allow:  al,
		ln:     ln,
		dialer: net.Dialer{Timeout: 15 * time.Second},
	}
	p.wg.Add(1)
	go p.serve()
	return p, nil
}

// Addr is the host:port the proxy listens on, e.g. "127.0.0.1:54321".
func (p *Proxy) Addr() string { return p.ln.Addr().String() }

// OnDenied registers a callback invoked with the host:port each time a
// connection is refused because it is not on the allowlist. Used for
// audit logging. Safe to leave unset.
func (p *Proxy) OnDenied(fn func(host string)) { p.onDenied = fn }

// Close stops accepting, waits for in-flight connections to drain, and
// releases the listener.
func (p *Proxy) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()
	err := p.ln.Close()
	p.wg.Wait()
	return err
}

func (p *Proxy) serve() {
	defer p.wg.Done()
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			p.mu.Lock()
			closed := p.closed
			p.mu.Unlock()
			if closed {
				return
			}
			continue
		}
		p.wg.Go(func() {
			p.handle(conn)
		})
	}
}

func (p *Proxy) handle(client net.Conn) {
	defer client.Close()
	br := bufio.NewReader(client)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method == http.MethodConnect {
		p.handleConnect(client, req)
		return
	}
	p.handlePlain(client, req)
}

// handleConnect tunnels a CONNECT request: check the target against the
// allowlist, dial it, reply 200, then splice bytes both ways.
func (p *Proxy) handleConnect(client net.Conn, req *http.Request) {
	host := req.Host // CONNECT authority is always host:port
	if !p.allow.permit(host) {
		p.deny(client, host)
		return
	}
	upstream, err := p.dialer.Dial("tcp", host)
	if err != nil {
		fmt.Fprintf(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer upstream.Close()
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	splice(client, upstream)
}

// handlePlain forwards an absolute-form http request (e.g. GET
// http://host/path). It rebuilds the request to origin form and streams
// the response back.
func (p *Proxy) handlePlain(client net.Conn, req *http.Request) {
	if req.URL == nil || req.URL.Host == "" {
		fmt.Fprintf(client, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}
	host := req.URL.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "80")
	}
	if !p.allow.permit(host) {
		p.deny(client, host)
		return
	}
	upstream, err := p.dialer.Dial("tcp", host)
	if err != nil {
		fmt.Fprintf(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer upstream.Close()
	// Send the request in origin form: strip the scheme://host prefix,
	// drop hop-by-hop proxy headers. Close after one exchange so the
	// upstream half signals EOF and the copy below can finish (we do not
	// pool keepalive connections here).
	req.RequestURI = ""
	req.URL.Scheme = ""
	req.URL.Host = ""
	req.Header.Del("Proxy-Connection")
	req.Close = true
	if err := req.Write(upstream); err != nil {
		return
	}
	// Pump the response back. Upstream closes when done (req.Close), so
	// this returns and the handler unwinds cleanly.
	_, _ = io.Copy(client, upstream)
}

func (p *Proxy) deny(client net.Conn, host string) {
	if p.onDenied != nil {
		p.onDenied(host)
	}
	fmt.Fprintf(client, "HTTP/1.1 403 Forbidden\r\n"+
		"Content-Type: text/plain\r\n\r\n"+
		"hako: host %q is not on the allowlist\n", host)
}

// splice copies bytes in both directions until either side closes.
func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		// Unblock the other direction by ending its read.
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			c.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

// ProxyEnv is the set of environment variables that point a child's
// HTTP client stack at addr. Both upper and lower case are set because
// tools disagree on which they read.
func ProxyEnv(addr string) map[string]string {
	url := "http://" + addr
	return map[string]string{
		"HTTP_PROXY":  url,
		"HTTPS_PROXY": url,
		"ALL_PROXY":   url,
		"http_proxy":  url,
		"https_proxy": url,
		"all_proxy":   url,
		"NO_PROXY":    "",
		"no_proxy":    "",
	}
}
