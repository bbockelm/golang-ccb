package wscarrier

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-ccb/internal/proxytest"
)

// TestWSCarrierThroughProxy is the core of the HPC-site case: the carrier is
// established over a CONNECT proxy, carries data, and -- the part that matters
// -- the proxy is where it actually went. Without the CONNECT assertion a
// carrier that ignored the proxy and dialed direct would pass this test.
func TestWSCarrierThroughProxy(t *testing.T) {
	serverTLS, clientTLS := selfSignedTLS(t)
	ln := startWS(t, serverTLS)
	proxy := proxytest.Start(t, nil)

	accCh := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accCh <- c
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cli, err := Dial(ctx, DialConfig{
		URL:   wsURL(ln, true),
		Token: "letmein",
		TLS:   clientTLS,
		Proxy: proxy.ProxyFunc(),
	})
	if err != nil {
		t.Fatalf("Dial through proxy: %v", err)
	}
	defer func() { _ = cli.Close() }()

	var srv net.Conn
	select {
	case srv = <-accCh:
	case <-time.After(10 * time.Second):
		t.Fatal("no Accept through the proxy")
	}
	defer func() { _ = srv.Close() }()

	if _, err := cli.Write([]byte("proxied")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := srv.Read(buf)
	if err != nil || string(buf[:n]) != "proxied" {
		t.Fatalf("read through the proxied carrier = %q, %v", buf[:n], err)
	}

	// The whole carrier is one CONNECT: that is the property a site that
	// throttles socket counts is buying.
	got := proxy.Connects()
	if len(got) != 1 {
		t.Fatalf("proxy saw %d CONNECTs, want exactly 1: %v", len(got), got)
	}
	if got[0] != ln.Addr().String() {
		t.Fatalf("proxy CONNECTed to %q, want the carrier endpoint %q", got[0], ln.Addr().String())
	}
}

// TestWSCarrierProxyRefusal: a proxy ACL that refuses the destination must
// surface as a clear error naming the refusal, not a timeout.
func TestWSCarrierProxyRefusal(t *testing.T) {
	serverTLS, clientTLS := selfSignedTLS(t)
	ln := startWS(t, serverTLS)
	proxy := proxytest.Start(t, proxytest.Deny(http.StatusForbidden))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := Dial(ctx, DialConfig{
		URL:   wsURL(ln, true),
		Token: "letmein",
		TLS:   clientTLS,
		Proxy: proxy.ProxyFunc(),
	})
	if err == nil {
		t.Fatal("Dial succeeded through a proxy that refuses CONNECT")
	}
	if !strings.Contains(err.Error(), "Forbidden") {
		t.Errorf("error does not name the proxy refusal: %v", err)
	}
	// The error must say which route was taken, or a refused proxy and a missing
	// proxy are indistinguishable in a log.
	if !strings.Contains(err.Error(), "via "+proxy.URL()) {
		t.Errorf("error does not name the route taken: %v", err)
	}
}

// TestWSCarrierProxyAuthorization: a proxy requiring authentication receives the
// credential from the proxy URL's userinfo.
func TestWSCarrierProxyAuthorization(t *testing.T) {
	serverTLS, clientTLS := selfSignedTLS(t)
	ln := startWS(t, serverTLS)
	proxy := proxytest.Start(t, nil)

	u, _ := url.Parse(proxy.URL())
	u.User = url.UserPassword("pilot", "s3cret")

	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cli, err := Dial(ctx, DialConfig{
		URL:   wsURL(ln, true),
		Token: "letmein",
		TLS:   clientTLS,
		Proxy: func(*http.Request) (*url.URL, error) { return u, nil },
	})
	if err != nil {
		t.Fatalf("Dial through an authenticating proxy: %v", err)
	}
	_ = cli.Close()

	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("pilot:s3cret"))
	seen := proxy.Authorizations()
	if len(seen) == 0 {
		t.Fatal("proxy received no Proxy-Authorization header")
	}
	if seen[0] != want {
		t.Errorf("Proxy-Authorization = %q, want %q", seen[0], want)
	}
}

// TestWSCarrierPlaintextThroughProxyRejected: ws:// through a proxy cannot work
// (a proxy is traversed with CONNECT, which http.Transport issues only for TLS),
// so it is refused before a connection is spent -- not left to fail obscurely
// when squid declines to relay the Upgrade.
func TestWSCarrierPlaintextThroughProxyRejected(t *testing.T) {
	ln := startWS(t, nil)
	proxy := proxytest.Start(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := Dial(ctx, DialConfig{
		URL:   wsURL(ln, false), // ws://, not wss://
		Token: "letmein",
		Proxy: proxy.ProxyFunc(),
	})
	if err == nil {
		t.Fatal("ws:// through a proxy was accepted")
	}
	if !strings.Contains(err.Error(), "requires wss://") {
		t.Errorf("error does not explain the scheme requirement: %v", err)
	}
	if got := proxy.Connects(); len(got) != 0 {
		t.Errorf("rejected dial still touched the proxy: %v", got)
	}
}

// TestResolvedProxyFromEnvironment: an unset DialConfig.Proxy honours
// HTTPS_PROXY and NO_PROXY, which is how a site's existing environment reaches
// the carrier with no CCB configuration at all. (A non-loopback host is used
// because Go's ProxyFromEnvironment never proxies localhost.)
func TestResolvedProxyFromEnvironment(t *testing.T) {
	const endpoint = "wss://ccb.offsite.test/ccb/tunnel"
	t.Setenv("HTTPS_PROXY", "http://squid.site:3128")
	t.Setenv("NO_PROXY", "")

	got, err := DialConfig{URL: endpoint}.ResolvedProxy()
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Host != "squid.site:3128" {
		t.Fatalf("ResolvedProxy = %v, want squid.site:3128 from HTTPS_PROXY", got)
	}

	t.Setenv("NO_PROXY", "offsite.test")
	got, err = DialConfig{URL: endpoint}.ResolvedProxy()
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("ResolvedProxy = %v, want direct for a NO_PROXY host", got)
	}
}

// TestNoProxyOverridesEnvironment: an explicit direct dial beats the
// environment, so a node that must not use the site proxy can say so.
func TestNoProxyOverridesEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://squid.site:3128")
	t.Setenv("NO_PROXY", "")
	got, err := DialConfig{URL: "wss://ccb.offsite.test/ccb/tunnel", Proxy: NoProxy}.ResolvedProxy()
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("ResolvedProxy with NoProxy = %v, want nil", got)
	}
}

// --- the staged health check ---

func stageByName(t *testing.T, res ProbeResult, want Stage) StageResult {
	t.Helper()
	for _, st := range res.Stages {
		if st.Stage == want {
			return st
		}
	}
	t.Fatalf("report has no %s stage:\n%s", want, res)
	return StageResult{}
}

// TestProbePassesThroughProxy: every stage of the health check passes against a
// real proxied endpoint, and the report names the route.
func TestProbePassesThroughProxy(t *testing.T) {
	serverTLS, clientTLS := selfSignedTLS(t)
	ln := startWS(t, serverTLS)
	proxy := proxytest.Start(t, nil)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res := Probe(ctx, DialConfig{
		URL:   wsURL(ln, true),
		Token: "letmein",
		TLS:   clientTLS,
		Proxy: proxy.ProxyFunc(),
	})
	if err := res.Err(); err != nil {
		t.Fatalf("probe failed: %v\n%s", err, res)
	}
	if res.Route != "via "+proxy.URL() {
		t.Errorf("Route = %q, want the proxy", res.Route)
	}
	for _, want := range []Stage{StageReachable, StageConnect, StageTLS, StageUpgrade} {
		if st := stageByName(t, res, want); st.Skipped {
			t.Errorf("stage %s was skipped but should have run:\n%s", want, res)
		}
	}
	// The TLS stage must report the certificate, since that is what makes an
	// intercepting proxy recognizable.
	if d := stageByName(t, res, StageTLS).Detail; !strings.Contains(d, "issuer") {
		t.Errorf("TLS stage does not report the certificate: %q", d)
	}
}

// TestProbeNamesRefusedConnect: the stage that fails is the proxy's, and the
// advice names the squid policy that most often causes it.
func TestProbeNamesRefusedConnect(t *testing.T) {
	serverTLS, clientTLS := selfSignedTLS(t)
	ln := startWS(t, serverTLS)
	proxy := proxytest.Start(t, proxytest.Deny(http.StatusForbidden))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res := Probe(ctx, DialConfig{URL: wsURL(ln, true), Token: "letmein", TLS: clientTLS, Proxy: proxy.ProxyFunc()})
	if res.OK() {
		t.Fatalf("probe passed against a refusing proxy:\n%s", res)
	}
	if st := stageByName(t, res, StageReachable); st.Err != nil {
		t.Errorf("TCP stage should pass -- the proxy is up: %v", st.Err)
	}
	st := stageByName(t, res, StageConnect)
	if st.Err == nil {
		t.Fatalf("proxy-connect stage passed:\n%s", res)
	}
	// The endpoint is on an ephemeral port, so the advice must point at the
	// SSL_ports rule -- the first thing to check at a real site.
	if !strings.Contains(st.Advice, "443") {
		t.Errorf("advice does not mention the port policy: %q", st.Advice)
	}
}

// TestProbeNamesUnreachableProxy: a proxy that is not listening fails the first
// stage, and says so in terms of the proxy rather than the endpoint.
func TestProbeNamesUnreachableProxy(t *testing.T) {
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := dead.Addr().String()
	_ = dead.Close() // nothing listens here now

	u, _ := url.Parse("http://" + addr)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res := Probe(ctx, DialConfig{
		URL:   "wss://ccb.offsite.test/ccb/tunnel",
		Token: "letmein",
		Proxy: func(*http.Request) (*url.URL, error) { return u, nil },
	})
	if res.OK() {
		t.Fatal("probe passed with no proxy listening")
	}
	st := stageByName(t, res, StageReachable)
	if st.Err == nil {
		t.Fatalf("tcp-reachable passed:\n%s", res)
	}
	if !strings.Contains(st.Advice, "proxy") {
		t.Errorf("advice does not blame the proxy: %q", st.Advice)
	}
}

// TestProbeNamesBadToken: transport stages pass and only the authenticated
// upgrade fails, which localizes the problem to the credential.
func TestProbeNamesBadToken(t *testing.T) {
	serverTLS, clientTLS := selfSignedTLS(t)
	ln := startWS(t, serverTLS)
	proxy := proxytest.Start(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res := Probe(ctx, DialConfig{URL: wsURL(ln, true), Token: "wrong", TLS: clientTLS, Proxy: proxy.ProxyFunc()})
	if res.OK() {
		t.Fatalf("probe passed with a rejected token:\n%s", res)
	}
	for _, s := range []Stage{StageReachable, StageConnect, StageTLS} {
		if st := stageByName(t, res, s); st.Err != nil {
			t.Errorf("stage %s should pass with a bad token: %v", s, st.Err)
		}
	}
	st := stageByName(t, res, StageUpgrade)
	if st.Err == nil {
		t.Fatalf("upgrade stage passed with a bad token:\n%s", res)
	}
	if !strings.Contains(st.Advice, "token") {
		t.Errorf("advice does not blame the token: %q", st.Advice)
	}
}

// TestProbeDetectsTLSInterception: a proxy that re-signs the endpoint's
// certificate (TLS bumping, common at HPC sites) fails the TLS stage with advice
// naming the issuer and the CA knob -- the only way to tell interception from a
// plain misconfiguration.
func TestProbeDetectsTLSInterception(t *testing.T) {
	serverTLS, _ := selfSignedTLS(t)      // the endpoint's real identity
	_, otherClientTLS := selfSignedTLS(t) // a client trusting a different CA
	ln := startWS(t, serverTLS)
	proxy := proxytest.Start(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res := Probe(ctx, DialConfig{URL: wsURL(ln, true), Token: "letmein", TLS: otherClientTLS, Proxy: proxy.ProxyFunc()})
	if res.OK() {
		t.Fatalf("probe passed against an untrusted certificate:\n%s", res)
	}
	if st := stageByName(t, res, StageConnect); st.Err != nil {
		t.Errorf("proxy-connect should pass: %v", st.Err)
	}
	st := stageByName(t, res, StageTLS)
	if st.Err == nil {
		t.Fatalf("TLS stage passed against an untrusted certificate:\n%s", res)
	}
	if !strings.Contains(st.Advice, "CCB_CARRIER_CA_FILE") {
		t.Errorf("advice does not name the CA knob: %q", st.Advice)
	}
	if !strings.Contains(st.Advice, "issued by") {
		t.Errorf("advice does not name the presented issuer: %q", st.Advice)
	}
}

// TestProbeSkipsTLSForPlaintext: a ws:// endpoint has no TLS stage, and the
// report says so rather than silently omitting it.
func TestProbeSkipsTLSForPlaintext(t *testing.T) {
	ln := startWS(t, nil)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res := Probe(ctx, DialConfig{URL: wsURL(ln, false), Token: "letmein", Proxy: NoProxy})
	if err := res.Err(); err != nil {
		t.Fatalf("direct ws:// probe failed: %v\n%s", err, res)
	}
	if st := stageByName(t, res, StageTLS); !st.Skipped {
		t.Errorf("TLS stage should be skipped for ws://:\n%s", res)
	}
	if st := stageByName(t, res, StageConnect); !st.Skipped {
		t.Errorf("proxy-connect stage should be skipped with no proxy:\n%s", res)
	}
	if res.Route != "direct" {
		t.Errorf("Route = %q, want direct", res.Route)
	}
}
