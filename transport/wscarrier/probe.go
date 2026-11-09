package wscarrier

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// A carrier dial crosses four independent things that can each be broken by a
// site's network policy, and a single "dial failed" says nothing about which:
// the proxy may be unreachable, it may refuse CONNECT to this destination, it
// may intercept TLS, or the token may be rejected. Probe walks them in order and
// reports each one separately, so the first failing stage names the problem --
// and, where the cause is a familiar site policy, says what to do about it.
//
// Probe is diagnostic: it opens its own connections and closes them. It is run
// at startup and by the `-carrier-check` mode, before any CCB machinery depends
// on the carrier.

// Stage names one layer of the carrier path, in the order a dial traverses it.
type Stage string

const (
	// StageReachable is a TCP connection to the proxy, or to the endpoint itself
	// when no proxy is configured.
	StageReachable Stage = "tcp-reachable"
	// StageConnect is the proxy's CONNECT response: whether it will tunnel to
	// this destination at all. Skipped when no proxy is configured.
	StageConnect Stage = "proxy-connect"
	// StageTLS is the TLS handshake with the endpoint. Skipped for ws://.
	StageTLS Stage = "tls"
	// StageUpgrade is the authenticated WebSocket upgrade: the real dial.
	StageUpgrade Stage = "websocket-upgrade"
)

// StageResult is the outcome of one stage.
type StageResult struct {
	Stage   Stage
	Skipped bool
	// Detail describes what was observed, on success or failure.
	Detail string
	Err    error
	// Advice names the likely site-policy cause and the fix, when one is known.
	Advice  string
	Elapsed time.Duration
}

// ProbeResult is the full report.
type ProbeResult struct {
	URL    string
	Route  string
	Stages []StageResult
}

// OK reports whether every non-skipped stage passed.
func (r ProbeResult) OK() bool { return r.Err() == nil }

// Err returns the first stage failure, with its advice attached, or nil.
func (r ProbeResult) Err() error {
	for _, st := range r.Stages {
		if st.Err != nil {
			if st.Advice != "" {
				return fmt.Errorf("%s: %w (%s)", st.Stage, st.Err, st.Advice)
			}
			return fmt.Errorf("%s: %w", st.Stage, st.Err)
		}
	}
	return nil
}

// String renders the report as one line per stage, for a log or a terminal.
func (r ProbeResult) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "carrier %s (%s)\n", r.URL, r.Route)
	for _, st := range r.Stages {
		switch {
		case st.Skipped:
			fmt.Fprintf(&b, "  SKIP %-18s %s\n", st.Stage, st.Detail)
		case st.Err != nil:
			fmt.Fprintf(&b, "  FAIL %-18s %v\n", st.Stage, st.Err)
			if st.Advice != "" {
				fmt.Fprintf(&b, "       %s\n", st.Advice)
			}
		default:
			fmt.Fprintf(&b, "  ok   %-18s %s (%s)\n", st.Stage, st.Detail, st.Elapsed.Round(time.Millisecond))
		}
	}
	return b.String()
}

// Append adds a stage to the report; callers layering their own checks on top of
// the transport (an end-to-end handshake, say) use this so one report covers the
// whole path.
func (r *ProbeResult) Append(st StageResult) { r.Stages = append(r.Stages, st) }

// Probe checks, stage by stage, whether cfg could establish a carrier.
func Probe(ctx context.Context, cfg DialConfig) ProbeResult {
	res := ProbeResult{URL: cfg.URL}

	proxyURL, err := cfg.ResolvedProxy()
	if err != nil {
		res.Route = "unresolved"
		res.Append(StageResult{Stage: StageReachable, Err: err})
		return res
	}
	res.Route = RouteDescription(proxyURL)

	endpoint, err := endpointHostPort(cfg.URL)
	if err != nil {
		res.Append(StageResult{Stage: StageReachable, Err: err})
		return res
	}
	secure := strings.HasPrefix(cfg.URL, "wss://") || strings.HasPrefix(cfg.URL, "https://")

	timeout := cfg.HandshakeTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	// Stage 1: TCP to whichever host we actually dial.
	hop := endpoint
	if proxyURL != nil {
		hop = proxyHostPort(proxyURL)
	}
	start := time.Now()
	d := net.Dialer{}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	conn, err := d.DialContext(tctx, "tcp", hop)
	cancel()
	st := StageResult{Stage: StageReachable, Elapsed: time.Since(start)}
	if err != nil {
		st.Err = err
		if proxyURL != nil {
			st.Advice = fmt.Sprintf("cannot reach the proxy %s itself; check CCB_CARRIER_PROXY and that the node may reach the proxy's port", hop)
		} else {
			st.Advice = "no proxy is configured, so this was a direct dial; on a node with no outbound route set CCB_CARRIER_PROXY (or HTTPS_PROXY) to the site proxy"
		}
		res.Append(st)
		return res
	}
	st.Detail = "connected to " + hop
	res.Append(st)
	defer func() { _ = conn.Close() }()

	// Stage 2: will the proxy tunnel to this destination?
	if proxyURL == nil {
		res.Append(StageResult{Stage: StageConnect, Skipped: true, Detail: "no proxy configured"})
	} else {
		start = time.Now()
		st := StageResult{Stage: StageConnect}
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			st.Err = err
			res.Append(st)
			return res
		}
		code, status, err := proxyConnect(conn, endpoint, proxyURL)
		st.Elapsed = time.Since(start)
		_ = conn.SetDeadline(time.Time{})
		switch {
		case err != nil:
			st.Err = err
			st.Advice = "the proxy did not answer the CONNECT request; it may not permit CONNECT at all"
		case code == http.StatusOK:
			st.Detail = fmt.Sprintf("proxy tunneled to %s", endpoint)
		default:
			st.Err = fmt.Errorf("proxy refused CONNECT to %s: %s", endpoint, status)
			st.Advice = connectAdvice(code, endpoint)
		}
		res.Append(st)
		if st.Err != nil {
			return res
		}
	}

	// Stage 3: TLS, and what certificate came back. A site proxy that intercepts
	// TLS shows up here as an unknown authority, with its own CA named -- which
	// is the only way to tell interception apart from a plain misconfiguration.
	if !secure {
		res.Append(StageResult{Stage: StageTLS, Skipped: true, Detail: "ws:// endpoint is plaintext"})
	} else {
		start = time.Now()
		st := StageResult{Stage: StageTLS}
		tlsCfg := &tls.Config{}
		if cfg.TLS != nil {
			tlsCfg = cfg.TLS.Clone()
		}
		if tlsCfg.ServerName == "" {
			host, _, _ := net.SplitHostPort(endpoint)
			tlsCfg.ServerName = host
		}
		tc := tls.Client(conn, tlsCfg)
		hctx, cancel := context.WithTimeout(ctx, timeout)
		err := tc.HandshakeContext(hctx)
		cancel()
		st.Elapsed = time.Since(start)
		if err != nil {
			st.Err = err
			var unknown x509.UnknownAuthorityError
			if errors.As(err, &unknown) {
				issuer := "an unknown CA"
				if unknown.Cert != nil {
					issuer = fmt.Sprintf("%q", unknown.Cert.Issuer.String())
				}
				st.Advice = fmt.Sprintf("the certificate presented for %s was issued by %s; if the site proxy intercepts TLS, add its CA to CCB_CARRIER_CA_FILE -- and note that an intercepting proxy sees the bearer token in the upgrade request, so prefer a short-lived, audience-scoped one", tlsCfg.ServerName, issuer)
			} else {
				st.Advice = "the endpoint did not complete a TLS handshake; check that it serves wss:// on this port"
			}
			res.Append(st)
			return res
		}
		cs := tc.ConnectionState()
		if len(cs.PeerCertificates) > 0 {
			leaf := cs.PeerCertificates[0]
			st.Detail = fmt.Sprintf("%s, subject %q, issuer %q, expires %s",
				tls.VersionName(cs.Version), leaf.Subject.CommonName, leaf.Issuer.CommonName,
				leaf.NotAfter.UTC().Format(time.RFC3339))
		} else {
			st.Detail = tls.VersionName(cs.Version)
		}
		res.Append(st)
		_ = tc.Close()
	}

	// Stage 4: the real, authenticated upgrade, over its own connection.
	start = time.Now()
	st = StageResult{Stage: StageUpgrade}
	pipe, err := Dial(ctx, cfg)
	st.Elapsed = time.Since(start)
	if err != nil {
		st.Err = err
		if strings.Contains(err.Error(), "unauthorized") {
			st.Advice = "the far broker rejected the bearer token; check CCB_CARRIER_TOKEN (or token discovery) and that the broker trusts its issuer"
		} else {
			st.Advice = "TCP, CONNECT and TLS all succeeded, so the far end is reachable but did not complete the WebSocket upgrade; check that it serves the carrier path in CCB_CARRIER_LISTEN"
		}
		res.Append(st)
		return res
	}
	_ = pipe.Close()
	st.Detail = "upgrade accepted and authenticated"
	res.Append(st)
	return res
}

// connectAdvice maps a proxy's CONNECT refusal to the site policy that usually
// causes it. These three are, in practice, every first-day failure at a site
// that requires a proxy.
func connectAdvice(code int, endpoint string) string {
	_, port, _ := net.SplitHostPort(endpoint)
	switch code {
	case http.StatusForbidden, http.StatusMethodNotAllowed:
		advice := fmt.Sprintf("the proxy's ACLs do not approve %s", endpoint)
		if port != "443" {
			advice += fmt.Sprintf("; note that a stock squid denies CONNECT to any port but 443 (acl SSL_ports), and this endpoint is on port %s -- serve the carrier on 443", port)
		} else {
			advice += "; ask the site to approve this hostname as a CONNECT destination"
		}
		return advice
	case http.StatusProxyAuthRequired:
		return "the proxy requires authentication; set CCB_CARRIER_PROXY_CREDENTIAL_FILE to a file holding user:password"
	case http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusGatewayTimeout:
		return fmt.Sprintf("the proxy accepted the request but could not reach %s; check the hostname resolves at the proxy and that the far broker is listening", endpoint)
	default:
		return ""
	}
}

// proxyConnect issues a CONNECT for endpoint over conn and returns the proxy's
// status. On 200 the connection is left positioned at the tunneled byte stream.
func proxyConnect(conn net.Conn, endpoint string, proxyURL *url.URL) (int, string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", endpoint, endpoint)
	if u := proxyURL.User; u != nil {
		pass, _ := u.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(u.Username() + ":" + pass))
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", cred)
	}
	b.WriteString("\r\n")
	if _, err := conn.Write([]byte(b.String())); err != nil {
		return 0, "", fmt.Errorf("writing CONNECT: %w", err)
	}
	// A 200 leaves the tunnel open with no body, so read only the headers and
	// hand the rest of the stream back untouched.
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Host: endpoint}}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return 0, "", fmt.Errorf("reading CONNECT response: %w", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Status, nil
}

// endpointHostPort is the host:port a carrier URL names, defaulting the port by
// scheme.
func endpointHostPort(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("wscarrier: bad URL %q: %w", rawURL, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("wscarrier: URL %q names no host", rawURL)
	}
	if u.Port() != "" {
		return u.Host, nil
	}
	switch u.Scheme {
	case "wss", "https":
		return net.JoinHostPort(u.Hostname(), "443"), nil
	default:
		return net.JoinHostPort(u.Hostname(), "80"), nil
	}
}

// proxyHostPort is the host:port of a proxy URL, defaulting the port.
func proxyHostPort(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	if u.Scheme == "https" {
		return net.JoinHostPort(u.Hostname(), "443")
	}
	return net.JoinHostPort(u.Hostname(), "80")
}
