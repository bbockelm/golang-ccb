package ccbserver

import (
	"context"
	"testing"
	"time"

	"github.com/bbockelm/golang-ccb/internal/proxytest"
)

// A glidein's carrier is idle most of the time: a node with nothing to do makes
// no connections for hours. Site proxies do not keep a quiet tunnel open --
// squid's read_timeout defaults to 15 minutes and sites shorten it -- so the
// carrier has to generate its own traffic or it is dropped, and the EP
// disappears from the pool until something notices.
//
// These use a proxy that drops a tunnel after a short idle period, which is the
// same failure in miniature.

// idleThenUse establishes a carrier through an idle-limited proxy, lets it go
// quiet for longer than the proxy tolerates, uses it again, and reports how many
// tunnels the proxy had to open for the whole episode.
//
// The count is the measurement, not whether the final call succeeded. A dropped
// carrier is re-established transparently on next use, so the call succeeds
// either way -- the difference between a carrier that stayed up and one that
// churned is visible only in the proxy's own record. Asserting on success would
// pass whatever the keepalive did.
func idleThenUse(t *testing.T, keepalive time.Duration, proxyIdle, quiet time.Duration) (tunnels int, err error) {
	t.Helper()
	carrierURL, serverTLS, clientTLS := wssCarrier(t)
	proxy := proxytest.StartWithIdleTimeout(t, proxyIdle)
	targetIP := nonLoopbackIPv4(t)

	served := make(chan struct{}, 2)
	targetAddr, stopTgt := startLingeringDialTarget(t, targetIP, served)
	defer stopTgt()

	_, _, stopOut := startOutsideWSSCCB(t, carrierURL, serverTLS, []string{targetIP + "/32"})
	defer stopOut()

	cfg := insideWSSConfig("", carrierURL, clientTLS, proxy, true)
	cfg.CarrierKeepalive = keepalive
	insideAddr, insideSrv, _, stopIn := startInsideWSSCCBConfig(t, cfg)
	defer stopIn()

	rctx, rcancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer rcancel()
	if err := insideSrv.WaitTunnelReady(rctx); err != nil {
		t.Fatalf("carrier never came up: %v", err)
	}

	// Prove it works before the idle period, so a failure afterwards is about
	// the idling and not about the setup.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	err = outboundDCNop(ctx, insideAddr, "<"+targetAddr+">")
	cancel()
	if err != nil {
		t.Fatalf("carrier did not work even before idling: %v", err)
	}

	time.Sleep(quiet)

	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err = outboundDCNop(ctx, insideAddr, "<"+targetAddr+">")
	return len(proxy.Connects()), err
}

// TestCarrierSurvivesProxyIdleTimeout: with a keepalive shorter than the
// proxy's patience, a quiet carrier stays up.
func TestCarrierSurvivesProxyIdleTimeout(t *testing.T) {
	const proxyIdle = 1500 * time.Millisecond
	tunnels, err := idleThenUse(t, 400*time.Millisecond, proxyIdle, 4*time.Second)
	if err != nil {
		t.Fatalf("carrier unusable after %s of quiet: %v", 4*time.Second, err)
	}
	if tunnels != 1 {
		t.Errorf("the proxy opened %d tunnels across the idle period, want 1; "+
			"the keepalive did not hold the tunnel open", tunnels)
	}
}

// TestCarrierKeepaliveTooSlowIsDropped is the negative control: the same setup
// with a keepalive SLOWER than the proxy's timeout must fail. Without it, the
// test above would pass on any carrier that happened to stay up for other
// reasons, and would not be testing the keepalive at all.
func TestCarrierKeepaliveTooSlowIsDropped(t *testing.T) {
	const proxyIdle = 1500 * time.Millisecond
	tunnels, err := idleThenUse(t, 30*time.Second, proxyIdle, 4*time.Second)
	// The call still succeeds -- that is the point: the carrier was dropped and
	// quietly rebuilt. Only the tunnel count shows it happened.
	if tunnels < 2 {
		t.Fatalf("the proxy opened %d tunnels with a %s keepalive behind a proxy that drops "+
			"after %s; the idle timeout is not being applied, so the positive test proves nothing",
			tunnels, 30*time.Second, proxyIdle)
	}
	t.Logf("as expected, a too-slow keepalive cost %d tunnels (err=%v)", tunnels, err)
}
