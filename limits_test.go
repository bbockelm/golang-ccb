package ccbserver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

// mapConfig looks knobs up case-insensitively, as HTCondor configuration does.
func mapConfig(m map[string]string) func(string) (string, bool) {
	up := map[string]string{}
	for k, v := range m {
		up[strings.ToUpper(k)] = v
	}
	return func(k string) (string, bool) {
		v, ok := up[strings.ToUpper(k)]
		return v, ok
	}
}

func TestLimitsFromConfigDefaults(t *testing.T) {
	got, err := LimitsFromConfig(mapConfig(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, DefaultLimits()) {
		t.Errorf("empty configuration = %+v, want DefaultLimits", got)
	}
}

func TestLimitsFromConfigDisabled(t *testing.T) {
	got, err := LimitsFromConfig(mapConfig(map[string]string{
		"CCB_LIMIT_ENABLE":       "false",
		"CCB_LIMIT_REQUEST_RATE": "not even parsed",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, Limits{}) {
		t.Errorf("CCB_LIMIT_ENABLE=false gave %+v, want the zero Limits", got)
	}
}

// TestLimitsFromConfigClasses: a class takes the default class's values
// (including ones the configuration changed) and overrides only what it sets.
func TestLimitsFromConfigClasses(t *testing.T) {
	got, err := LimitsFromConfig(mapConfig(map[string]string{
		"CCB_LIMIT_REQUEST_RATE":                "10",
		"CCB_LIMIT_REQUEST_BURST":               "40",
		"CCB_LIMIT_CLASSES":                     "offsite, campus",
		"CCB_LIMIT_offsite_NETWORKS":            "0.0.0.0/0, ::/0",
		"CCB_LIMIT_OFFSITE_REGISTER_RATE":       "0.5",
		"CCB_LIMIT_OFFSITE_REGISTER_CLASS_RATE": "20",
		"CCB_LIMIT_OFFSITE_MAX_SPLICES":         "8",
		"CCB_LIMIT_OFFSITE_BANDWIDTH_RATE":      "10M",
		"CCB_LIMIT_CAMPUS_NETWORKS":             "192.0.2.0/24 2001:db8::/32 198.51.100.7",
		"CCB_LIMIT_CAMPUS_REQUEST_RATE":         "0",
		"CCB_LIMIT_BANDWIDTH_TOTAL_RATE":        "1G",
		"CCB_LIMIT_MAX_WAIT":                    "2.5",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got.Default.Request != (Rate{PerSecond: 10, Burst: 40}) {
		t.Errorf("default request = %+v", got.Default.Request)
	}
	if len(got.Classes) != 2 {
		t.Fatalf("classes = %+v", got.Classes)
	}
	off, campus := got.Classes[0].Limits, got.Classes[1].Limits
	if off.Request != (Rate{PerSecond: 10, Burst: 40}) {
		t.Errorf("offsite request = %+v, want the configured default", off.Request)
	}
	if off.Register != (Rate{PerSecond: 0.5}) {
		t.Errorf("offsite register = %+v, want 0.5/s with a derived burst", off.Register)
	}
	if off.RegisterClass.PerSecond != 20 || off.MaxSplices != 8 || off.Bandwidth.PerSecond != 10<<20 {
		t.Errorf("offsite overrides not applied: %+v", off)
	}
	if off.Connect != DefaultLimits().Default.Connect {
		t.Errorf("offsite connect = %+v, want the built-in default", off.Connect)
	}
	if campus.Request.Limited() {
		t.Errorf("campus request = %+v, want unlimited", campus.Request)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("198.51.100.7/32"),
	}
	if !reflect.DeepEqual(got.Classes[1].Networks, want) {
		t.Errorf("campus networks = %v, want %v", got.Classes[1].Networks, want)
	}
	if got.Total.Bandwidth.PerSecond != 1<<30 {
		t.Errorf("total bandwidth = %+v", got.Total.Bandwidth)
	}
	if got.MaxWait != 2500*time.Millisecond {
		t.Errorf("max wait = %v", got.MaxWait)
	}
}

func TestLimitsFromConfigRejects(t *testing.T) {
	for name, cfg := range map[string]map[string]string{
		"class named like a knob": {
			"CCB_LIMIT_CLASSES":         "TARGET",
			"CCB_LIMIT_TARGET_NETWORKS": "10.0.0.0/8",
		},
		"reserved class": {
			"CCB_LIMIT_CLASSES":          "default",
			"CCB_LIMIT_DEFAULT_NETWORKS": "10.0.0.0/8",
		},
		"class listed twice": {
			"CCB_LIMIT_CLASSES":    "A a",
			"CCB_LIMIT_A_NETWORKS": "10.0.0.0/8",
		},
		"class without networks": {
			"CCB_LIMIT_CLASSES": "A",
		},
		"bad network": {
			"CCB_LIMIT_CLASSES":    "A",
			"CCB_LIMIT_A_NETWORKS": "10.0.0.0/33",
		},
		"bad class name": {
			"CCB_LIMIT_CLASSES": "a-b",
		},
		"negative rate": {
			"CCB_LIMIT_REQUEST_RATE": "-1",
		},
		"bad bandwidth": {
			"CCB_LIMIT_BANDWIDTH_RATE": "fast",
		},
		"prefix out of range": {
			"CCB_LIMIT_SOURCE_PREFIX_V4": "33",
		},
		"bad enable": {
			"CCB_LIMIT_ENABLE": "maybe",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LimitsFromConfig(mapConfig(cfg))
			if err == nil {
				t.Fatal("accepted")
			}
			t.Log(err)
		})
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]float64{
		"100": 100, "64K": 64 << 10, "10M": 10 << 20, "1.5G": 1.5 * (1 << 30),
		"10MB": 10 << 20, "10MiB": 10 << 20, "10M/s": 10 << 20, "2kb/s": 2 << 10,
	} {
		got, err := parseSize(in)
		if err != nil || got != want {
			t.Errorf("parseSize(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
}

// TestEveryLimitKnobIsParsed: each knob the parser lists is one it reads, so a
// knob added to the table and documented cannot silently do nothing.
func TestEveryLimitKnobIsParsed(t *testing.T) {
	for _, k := range classRateKnobs {
		l, err := LimitsFromConfig(mapConfig(map[string]string{k.rate: "7", k.burst: "9"}))
		if err != nil {
			t.Fatalf("%s: %v", k.rate, err)
		}
		if r := *k.field(&l.Default); r.PerSecond != 7 || r.Burst != 9 {
			t.Errorf("%s/%s set %+v", k.rate, k.burst, r)
		}
	}
	for _, k := range classIntKnobs {
		l, err := LimitsFromConfig(mapConfig(map[string]string{k.name: "7"}))
		if err != nil {
			t.Fatalf("%s: %v", k.name, err)
		}
		if n := *k.field(&l.Default); n != 7 {
			t.Errorf("%s set %d", k.name, n)
		}
	}
}

func testLimiter(t *testing.T, l Limits) *limiter {
	t.Helper()
	l.LimitLoopback = true
	lm, err := newLimiter(l, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return lm
}

func ep(s string) endpoint { return endpoint{addr: netip.MustParseAddr(s)} }

func TestClassifyLongestPrefix(t *testing.T) {
	p, err := compilePolicy(Limits{Classes: []NetworkClass{
		{Name: "WORLD", Networks: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}},
		{Name: "CAMPUS", Networks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
		{Name: "LAB", Networks: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}},
		{Name: "V6", Networks: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]string{
		"192.0.2.1":   "WORLD",
		"10.2.3.4":    "CAMPUS",
		"10.1.3.4":    "LAB",
		"2001:db8::1": "V6",
		"2001:db9::1": defaultClassName, // an IPv4 0/0 does not cover IPv6
	} {
		if got := p.classify(netip.MustParseAddr(addr)).name; got != want {
			t.Errorf("classify(%s) = %s, want %s", addr, got, want)
		}
	}
	if got := p.classify(netip.Addr{}).name; got != defaultClassName {
		t.Errorf("an endpoint with no address classified as %s", got)
	}
}

// TestPerSourceAndPerClassBuckets: sources get separate per-source buckets
// but share their class's, and an IPv6 /64 is one source.
func TestPerSourceAndPerClassBuckets(t *testing.T) {
	lm := testLimiter(t, Limits{Default: ClassLimits{
		Request:      Rate{PerSecond: 0.001, Burst: 1},
		RequestClass: Rate{PerSecond: 0.001, Burst: 3},
	}})
	ctx := context.Background()
	take := func(e endpoint) error { return lm.take(ctx, kindRequest, 0, e) }

	if err := take(ep("192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	err := take(ep("192.0.2.1"))
	var le *LimitError
	if !errors.As(err, &le) || le.Scope != "per-source" {
		t.Fatalf("second request from one source = %v, want a per-source refusal", err)
	}
	if err := take(ep("2001:db8::1")); err != nil {
		t.Fatalf("another source: %v", err)
	}
	if err := take(ep("2001:db8::ffff")); err == nil {
		t.Error("an address in the same /64 got a bucket of its own")
	}
	if err := take(ep("192.0.2.2")); err != nil {
		t.Fatalf("third source: %v", err)
	}
	err = take(ep("192.0.2.3"))
	if !errors.As(err, &le) || le.Scope != "per-class" {
		t.Fatalf("fourth source = %v, want a per-class refusal", err)
	}
	if !strings.Contains(err.Error(), "class DEFAULT") {
		t.Errorf("refusal %q does not name the class", err)
	}
}

// TestTakeQueuesWithinMaxWait: over its rate, an operation waits for a
// token if one comes within MaxWait, and is refused at once if not.
func TestTakeQueuesWithinMaxWait(t *testing.T) {
	lm := testLimiter(t, Limits{Default: ClassLimits{Register: Rate{PerSecond: 10, Burst: 1}}})
	ctx := context.Background()
	src := ep("192.0.2.1")
	if err := lm.take(ctx, kindRegister, 0, src); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := lm.take(ctx, kindRegister, time.Second, src); err != nil {
		t.Fatalf("queued register: %v", err)
	}
	if waited := time.Since(start); waited < 50*time.Millisecond {
		t.Errorf("queued register waited only %v at 10/s", waited)
	}
	if err := lm.take(ctx, kindRegister, 0, src); err == nil {
		t.Error("register over the rate with no wait allowed was admitted")
	}
	// A refused operation gives its reservation back: after one token's
	// time, exactly one more is admitted.
	time.Sleep(110 * time.Millisecond)
	if err := lm.take(ctx, kindRegister, 0, src); err != nil {
		t.Errorf("register after refill: %v", err)
	}
}

func TestLoopbackExemptByDefault(t *testing.T) {
	lm, err := newLimiter(Limits{Default: ClassLimits{Request: Rate{PerSecond: 0.001, Burst: 1}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	lo := lm.endpointForString("127.0.0.1:9618")
	for i := 0; i < 5; i++ {
		if err := lm.take(context.Background(), kindRequest, 0, lo); err != nil {
			t.Fatalf("loopback request %d: %v", i, err)
		}
	}
	if e := lm.endpointForString("[::ffff:192.0.2.1]:9618"); e.addr != netip.MustParseAddr("192.0.2.1") {
		t.Errorf("4-in-6 address kept as %v", e.addr)
	}
}

// TestAcquireCaps: concurrency caps at each scope, released on release, and
// a carrier endpoint skips the per-source cap only.
func TestAcquireCaps(t *testing.T) {
	lm := testLimiter(t, Limits{
		Default: ClassLimits{MaxSplices: 1, MaxSplicesClass: 2},
		Total:   TotalLimits{MaxSplices: 3},
		Classes: []NetworkClass{{Name: "OTHER", Networks: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
			Limits: ClassLimits{MaxSplicesClass: 10}}},
	})
	a, b, c := ep("192.0.2.1"), ep("192.0.2.2"), ep("192.0.2.3")
	relA, err := lm.acquire(kindSplices, a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lm.acquire(kindSplices, a); err == nil {
		t.Error("second splice from one source admitted over MaxSplices=1")
	}
	if _, err := lm.acquire(kindSplices, b); err != nil {
		t.Fatal(err)
	}
	if _, err := lm.acquire(kindSplices, c); err == nil {
		t.Error("third splice in the class admitted over MaxSplicesClass=2")
	}
	if _, err := lm.acquire(kindSplices, ep("198.51.100.1")); err != nil {
		t.Fatalf("another class: %v", err)
	}
	if _, err := lm.acquire(kindSplices, ep("198.51.100.2")); err == nil {
		t.Error("fourth splice admitted over the broker-wide MaxSplices=3")
	}
	relA()
	relA() // idempotent
	if _, err := lm.acquire(kindSplices, a); err != nil {
		t.Errorf("after release: %v", err)
	}
	carrierEp := endpoint{addr: netip.MustParseAddr("192.0.2.1"), noSource: true}
	if _, err := lm.acquire(kindSplices, carrierEp); err == nil {
		t.Error("the broker-wide cap did not apply to a carrier endpoint")
	}
}

// TestSpliceBothEndsCountedOnce: a splice whose two ends share a class
// counts once against that class.
func TestSpliceBothEndsCountedOnce(t *testing.T) {
	lm := testLimiter(t, Limits{Default: ClassLimits{MaxSplicesClass: 1}})
	if _, err := lm.acquire(kindSplices, ep("192.0.2.1"), ep("192.0.2.2")); err != nil {
		t.Fatalf("one splice between two sources of one class: %v", err)
	}
}

// TestSweepAndOverflow: refilled per-source buckets are forgotten, and
// sources beyond MaxTrackedSources share an overflow bucket.
func TestSweepAndOverflow(t *testing.T) {
	lm := testLimiter(t, Limits{
		Default:           ClassLimits{Request: Rate{PerSecond: 1000, Burst: 1}},
		MaxTrackedSources: 2,
	})
	ctx := context.Background()
	for _, s := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		_ = lm.take(ctx, kindRequest, 0, ep(s))
	}
	if n := lm.tracked[kindRequest]; n != 3 {
		t.Errorf("tracked = %d, want 2 sources and the overflow bucket", n)
	}
	if _, ok := lm.buckets[bucketKey{kind: kindRequest, scope: scopeSource, class: defaultClassName, source: overflowSource}]; !ok {
		t.Error("third source did not land in the overflow bucket")
	}
	lm.sweep(time.Now().Add(time.Second))
	if n := len(lm.buckets); n != 0 {
		t.Errorf("%d buckets survived a sweep after refill", n)
	}
}

// TestThrottledSplice: a paced relay moves no faster than its bandwidth
// limit, and still delivers every byte.
func TestThrottledSplice(t *testing.T) {
	lm := testLimiter(t, Limits{Default: ClassLimits{
		Bandwidth: Rate{PerSecond: 256 << 10, Burst: 32 << 10},
	}})
	lims := lm.bandwidthFor(ep("192.0.2.1"))
	if len(lims) != 1 {
		t.Fatalf("bandwidthFor = %d limiters, want 1", len(lims))
	}
	reqA, reqB := tcpPair(t)
	tgtA, tgtB := tcpPair(t)
	done := make(chan spliceStats, 1)
	go func() { done <- spliceConns(reqB, tgtA, lims...) }()

	const size = 384 << 10
	start := time.Now()
	go func() {
		_, _ = reqA.Write(make([]byte, size))
		_ = reqA.(*net.TCPConn).CloseWrite()
	}()
	n, err := io.Copy(io.Discard, tgtB)
	elapsed := time.Since(start)
	if err != nil || n != size {
		t.Fatalf("relayed %d bytes, err %v; want %d", n, err, size)
	}
	// 32K of burst, then 352K at 256K/s.
	if elapsed < 1200*time.Millisecond {
		t.Errorf("relayed %d bytes in %v; a 256K/s limit needs at least 1.3s", size, elapsed)
	}
	_ = tgtB.Close()
	_ = reqA.Close()
	<-done
}

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	acc := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		acc <- c
	}()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b := <-acc
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

// TestPerSpliceBandwidthTakesTheStricterEnd: of two ends' per-splice limits,
// the lower applies.
func TestPerSpliceBandwidthTakesTheStricterEnd(t *testing.T) {
	lm := testLimiter(t, Limits{
		Default: ClassLimits{BandwidthSplice: Rate{PerSecond: 1 << 20}},
		Classes: []NetworkClass{{Name: "SLOW", Networks: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
			Limits: ClassLimits{BandwidthSplice: Rate{PerSecond: 100 << 10}}}},
	})
	lims := lm.bandwidthFor(ep("192.0.2.1"), ep("198.51.100.1"))
	if len(lims) != 1 || float64(lims[0].Limit()) != 100<<10 {
		t.Fatalf("per-splice limit = %v, want 100K/s", lims)
	}
}
