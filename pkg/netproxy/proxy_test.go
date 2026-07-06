package netproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAllowlist(t *testing.T) {
	al, err := parseAllowlist([]string{
		"example.com",
		"api.test.com:443",
		"*.wild.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host string
		want bool
	}{
		{"example.com:443", true},
		{"example.com:80", true},   // no port constraint
		{"EXAMPLE.COM:443", true},  // case-insensitive
		{"api.test.com:443", true}, // exact port
		{"api.test.com:80", false}, // wrong port
		{"other.com:443", false},
		{"a.wild.com:443", true},   // subdomain
		{"a.b.wild.com:443", true}, // deep subdomain
		{"wild.com:443", false},    // apex not matched by *.
	}
	for _, c := range cases {
		if got := al.permit(c.host); got != c.want {
			t.Errorf("permit(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestProxyForwardsAllowed(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "backend-ok")
	}))
	defer backend.Close()

	// Allow exactly the backend's host:port.
	host := strings.TrimPrefix(backend.URL, "http://")
	p, err := Start([]string{host})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	client := proxyClient(t, p.Addr())
	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "backend-ok" {
		t.Errorf("body = %q, want backend-ok", body)
	}
}

func TestProxyBlocksDenied(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "should-not-reach")
	}))
	defer backend.Close()

	var denied []string
	p, err := Start([]string{"allowed.example:80"})
	if err != nil {
		t.Fatal(err)
	}
	p.OnDenied(func(h string) { denied = append(denied, h) })
	defer p.Close()

	client := proxyClient(t, p.Addr())
	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "should-not-reach") {
		t.Error("proxy forwarded to a denied host")
	}
	if len(denied) == 0 {
		t.Error("OnDenied was not called")
	}
}

func proxyClient(t *testing.T, addr string) *http.Client {
	t.Helper()
	u, err := url.Parse("http://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(u)},
	}
}
