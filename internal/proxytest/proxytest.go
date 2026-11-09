// Package proxytest provides an in-process HTTP CONNECT proxy and matching TLS
// material for tests that need to prove traffic crossed a proxy rather than
// going around it.
//
// It stands in for the site squid in the fast test tiers: it records every
// CONNECT it is asked for, so a test can assert the carrier actually used it,
// and it answers with whatever status its policy returns, which is how squid's
// ACL refusals (403 for an unapproved destination or a non-443 port, 407 for
// required authentication) are reproduced without a container.
//
// It deliberately does not emulate squid's timeouts, TLS interception or
// logging; those need the real thing (see docs/E2E_SQUID_WS.md).
package proxytest

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"
)

// Proxy is an in-process CONNECT proxy.
type Proxy struct {
	ln    net.Listener
	allow func(hostport string) int

	mu       sync.Mutex
	connects []string
	auth     []string
}

// Start runs a proxy whose policy is allow: the HTTP status to answer a CONNECT
// for a given host:port with (http.StatusOK tunnels). A nil allow permits
// everything. The proxy is closed when the test ends.
func Start(t *testing.T, allow func(hostport string) int) *Proxy {
	t.Helper()
	if allow == nil {
		allow = func(string) int { return http.StatusOK }
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{ln: ln, allow: allow}
	go p.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return p
}

// Deny is an allow function refusing every destination with code.
func Deny(code int) func(string) int { return func(string) int { return code } }

func (p *Proxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

func (p *Proxy) handle(c net.Conn) {
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		_ = c.Close()
		return
	}
	if req.Method != http.MethodConnect {
		_, _ = c.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		_ = c.Close()
		return
	}
	target := req.URL.Host
	p.mu.Lock()
	p.connects = append(p.connects, target)
	if a := req.Header.Get("Proxy-Authorization"); a != "" {
		p.auth = append(p.auth, a)
	}
	p.mu.Unlock()

	if code := p.allow(target); code != http.StatusOK {
		fmt.Fprintf(c, "HTTP/1.1 %d %s\r\n\r\n", code, http.StatusText(code))
		_ = c.Close()
		return
	}
	up, err := net.Dial("tcp", target)
	if err != nil {
		_, _ = c.Write([]byte("HTTP/1.1 503 Service Unavailable\r\n\r\n"))
		_ = c.Close()
		return
	}
	_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	go func() { _, _ = io.Copy(up, br); _ = up.Close() }()
	go func() { _, _ = io.Copy(c, up); _ = c.Close() }()
}

// URL is the proxy's address as an http:// URL.
func (p *Proxy) URL() string { return "http://" + p.ln.Addr().String() }

// Addr is the proxy's host:port.
func (p *Proxy) Addr() string { return p.ln.Addr().String() }

// ProxyFunc returns this proxy in the form http.Transport.Proxy (and the
// carrier's Proxy knob) takes.
func (p *Proxy) ProxyFunc() func(*http.Request) (*url.URL, error) {
	u, _ := url.Parse(p.URL())
	return func(*http.Request) (*url.URL, error) { return u, nil }
}

// Connects lists the host:port of every CONNECT the proxy was asked for, in
// order. Asserting on its length is how a test proves the carrier used the
// proxy -- and used only one connection for the whole session.
func (p *Proxy) Connects() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.connects...)
}

// Authorizations lists every Proxy-Authorization header value received.
func (p *Proxy) Authorizations() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.auth...)
}

// SelfSignedTLS returns a server tls.Config holding a fresh self-signed
// certificate for 127.0.0.1 and a client tls.Config that trusts it. Calling it
// twice yields two unrelated CAs, which is how a TLS-intercepting proxy is
// emulated (the client trusts one, the endpoint presents the other).
func SelfSignedTLS(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &tls.Config{Certificates: []tls.Certificate{tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}}},
		&tls.Config{RootCAs: pool}
}
