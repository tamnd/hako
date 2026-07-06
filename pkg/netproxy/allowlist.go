package netproxy

import (
	"fmt"
	"net"
	"strings"
)

// allowlist decides whether a host:port may be reached. Entries are
// matched on host (case-insensitive). An entry with a port permits only
// that port; an entry without one permits every port. A leading "*."
// matches any subdomain, e.g. "*.example.com" allows "api.example.com"
// but not "example.com" itself.
type allowlist struct {
	exact    map[string]*ports // host -> allowed ports
	suffixes []suffixRule      // *.domain rules
}

type suffixRule struct {
	suffix string // ".example.com"
	ports  *ports
}

// ports is the port constraint for a host. anyPort true means every
// port is allowed and set is ignored.
type ports struct {
	anyPort bool
	set     map[string]bool
}

func newPorts() *ports { return &ports{set: map[string]bool{}} }

func (p *ports) add(port string) {
	if port == "" {
		p.anyPort = true
		return
	}
	p.set[port] = true
}

func (p *ports) allows(port string) bool {
	return p.anyPort || p.set[port]
}

func parseAllowlist(hosts []string) (*allowlist, error) {
	al := &allowlist{exact: map[string]*ports{}}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		host, port, err := splitHostEntry(h)
		if err != nil {
			return nil, err
		}
		host = strings.ToLower(host)
		if rest, ok := strings.CutPrefix(host, "*."); ok {
			if rest == "" {
				return nil, fmt.Errorf("netproxy: bad host pattern %q", h)
			}
			r := suffixRule{suffix: "." + rest, ports: newPorts()}
			r.ports.add(port)
			al.suffixes = append(al.suffixes, r)
			continue
		}
		if al.exact[host] == nil {
			al.exact[host] = newPorts()
		}
		al.exact[host].add(port)
	}
	return al, nil
}

// permit reports whether hostport (always "host:port" here) is allowed.
func (a *allowlist) permit(hostport string) bool {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return false
	}
	host = strings.ToLower(host)
	if ps, ok := a.exact[host]; ok && ps.allows(port) {
		return true
	}
	for _, r := range a.suffixes {
		if strings.HasSuffix(host, r.suffix) && r.ports.allows(port) {
			return true
		}
	}
	return false
}

// splitHostEntry parses "host" or "host:port". Bare hosts are fine.
func splitHostEntry(s string) (host, port string, err error) {
	if !strings.Contains(s, ":") {
		return s, "", nil
	}
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", "", fmt.Errorf("netproxy: bad host %q: %w", s, err)
	}
	return h, p, nil
}
