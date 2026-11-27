package ccbserver

import (
	"fmt"
	"math"
	"net/netip"
	"strings"
	"time"
)

// Rate is a token bucket: PerSecond sustained, up to Burst at once. A zero
// PerSecond means no limit. A zero Burst with a non-zero PerSecond takes
// one second's worth of PerSecond (at least one operation, or, for a
// bandwidth limit, at least minBandwidthBurst bytes).
type Rate struct {
	PerSecond float64
	Burst     int
}

// Limited reports whether r limits anything.
func (r Rate) Limited() bool { return r.PerSecond > 0 }

func (r Rate) opBurst() int {
	if r.Burst > 0 {
		return r.Burst
	}
	return max(1, int(math.Ceil(r.PerSecond)))
}

// minBandwidthBurst is the smallest bucket a bandwidth limit gets, so a low
// rate still moves bytes in reasonably sized reads.
const minBandwidthBurst = 64 << 10

func (r Rate) byteBurst() int {
	if r.Burst > 0 {
		return r.Burst
	}
	return max(minBandwidthBurst, int(math.Min(r.PerSecond, math.MaxInt32)))
}

// ClassLimits are the limits applied to the sources in one network class.
//
// Rates come in two scopes. The unsuffixed field is per source: every source
// address (or source prefix, see SourcePrefixV4/V6) gets its own bucket. The
// ...Class field is one bucket shared by every source in the class, which is
// what bounds a whole network no matter how many addresses it spreads over.
// Zero values mean no limit.
type ClassLimits struct {
	// Connect is how often a source may open a connection to the broker. It
	// is checked before the security handshake, so it is what bounds the
	// cryptographic work a source can make the broker do.
	Connect, ConnectClass Rate
	// Register is how often a source may register a daemon (CCB_REGISTER).
	Register, RegisterClass Rate
	// Request is how often a source may ask for a connection to a registered
	// daemon (CCB_REQUEST).
	Request, RequestClass Rate
	// ProxyConnect is how often a source may ask the outbound proxy to dial
	// a target for it (CCB_PROXY_CONNECT).
	ProxyConnect, ProxyConnectClass Rate

	// MaxPending caps the connections one source may have open that have not
	// finished their security handshake. Without it one source can fill the
	// broker's whole pending-connection allowance and lock everyone else out.
	MaxPending int

	// MaxRegistrations caps the daemons one source (and the whole class) may
	// hold registered at once.
	MaxRegistrations, MaxRegistrationsClass int

	// MaxSplices caps the relayed connections (streaming mode or outbound
	// proxy) with an end in one source (and in the whole class).
	MaxSplices, MaxSplicesClass int

	// Bandwidth limits the bytes relayed, both directions together, for all
	// splices with an end in one source, for the whole class, and for each
	// single splice. Rates are in bytes per second; Burst is in bytes.
	Bandwidth, BandwidthClass, BandwidthSplice Rate

	// TargetRequest limits how often requests may be forwarded to one
	// registered daemon in this class (classified by the daemon's address),
	// whoever sends them. It protects the daemon, not the broker.
	TargetRequest Rate
	// TargetMaxPendingRequests caps the requests to one registered daemon
	// awaiting its answer.
	TargetMaxPendingRequests int
	// TargetMessage limits how fast the broker reads control messages
	// (heartbeats, results) from one registered daemon. Over it the broker
	// simply reads more slowly, so TCP pushes back on the daemon; nothing is
	// dropped.
	TargetMessage Rate

	// SourcePrefixV4 and SourcePrefixV6 set what counts as one source: the
	// address masked to this many bits. 0 means 32 and 64. A whole IPv6 /64
	// usually belongs to one host or one site, and an address-per-connection
	// client would otherwise get a fresh bucket every time.
	SourcePrefixV4, SourcePrefixV6 int
}

// NetworkClass is a named set of networks that gets its own limits.
type NetworkClass struct {
	Name     string
	Networks []netip.Prefix
	Limits   ClassLimits
}

// TotalLimits apply to the broker as a whole, whatever the source.
type TotalLimits struct {
	Connect, Register, Request, ProxyConnect Rate
	MaxRegistrations, MaxSplices             int
	Bandwidth                                Rate
}

// Limits is the broker's rate-limit policy. The zero value limits nothing;
// DefaultLimits is the recommended starting point.
type Limits struct {
	// Default applies to every source in no class.
	Default ClassLimits
	// Classes are matched by longest prefix: a source belongs to the class
	// with the most specific network containing it (the first listed, on a
	// tie). A class's ClassLimits are complete -- it does not inherit from
	// Default; LimitsFromConfig does that inheritance for configuration.
	Classes []NetworkClass
	Total   TotalLimits

	// MaxWait is how long a register, request or proxy-connect over its rate
	// may queue for a token before it is refused. Queueing smooths a burst
	// (every daemon behind a NAT re-registering after a broker restart) into
	// the configured rate instead of failing most of it. 0 refuses at once.
	// Connections are never queued: they are refused at accept.
	MaxWait time.Duration

	// LimitLoopback applies the limits to loopback sources too. By default
	// they are exempt, as the local condor_master and tools are.
	LimitLoopback bool

	// MaxTrackedSources bounds the per-source buckets kept for each limit.
	// Beyond it, new sources share one overflow bucket per class, which only
	// ever limits them harder. 0 means DefaultMaxTrackedSources.
	MaxTrackedSources int
}

// DefaultMaxTrackedSources is Limits.MaxTrackedSources's default.
const DefaultMaxTrackedSources = 100000

// DefaultLimits returns the broker's default policy.
//
// The per-source rates are set well above what one well-behaved host does --
// an access point asking for connections to a few dozen execute points a
// second, or a host registering its handful of daemons -- and well below what
// a client stuck in a reconnect loop does, which is the traffic they exist to
// stop. Concurrency caps, class aggregates and bandwidth are left unlimited:
// their right values depend on the pool's size and network, and a wrong
// default there breaks a legitimate deployment (thousands of daemons behind
// one NAT, a private schedd whose every shadow is relayed).
func DefaultLimits() Limits {
	return Limits{
		Default: ClassLimits{
			Connect:                  Rate{PerSecond: 50, Burst: 500},
			Register:                 Rate{PerSecond: 5, Burst: 100},
			Request:                  Rate{PerSecond: 50, Burst: 500},
			ProxyConnect:             Rate{PerSecond: 20, Burst: 200},
			MaxPending:               256,
			TargetRequest:            Rate{PerSecond: 20, Burst: 200},
			TargetMaxPendingRequests: 100,
			TargetMessage:            Rate{PerSecond: 50, Burst: 500},
		},
		MaxWait: 5 * time.Second,
	}
}

// validate checks l for values that cannot be enforced.
func (l *Limits) validate() error {
	if err := l.Default.validate("default"); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, c := range l.Classes {
		if c.Name == "" {
			return fmt.Errorf("ccbserver: a network class has no name")
		}
		key := strings.ToUpper(c.Name)
		if seen[key] {
			return fmt.Errorf("ccbserver: network class %q is defined twice", c.Name)
		}
		seen[key] = true
		if key == defaultClassName {
			return fmt.Errorf("ccbserver: network class name %q is reserved", c.Name)
		}
		if len(c.Networks) == 0 {
			return fmt.Errorf("ccbserver: network class %q lists no networks", c.Name)
		}
		for _, p := range c.Networks {
			if !p.IsValid() {
				return fmt.Errorf("ccbserver: network class %q has an invalid network", c.Name)
			}
		}
		if err := c.Limits.validate(c.Name); err != nil {
			return err
		}
	}
	for _, r := range []Rate{l.Total.Connect, l.Total.Register, l.Total.Request, l.Total.ProxyConnect, l.Total.Bandwidth} {
		if err := r.validate("total"); err != nil {
			return err
		}
	}
	if l.Total.MaxRegistrations < 0 || l.Total.MaxSplices < 0 || l.MaxWait < 0 || l.MaxTrackedSources < 0 {
		return fmt.Errorf("ccbserver: limits must not be negative")
	}
	return nil
}

func (c *ClassLimits) validate(class string) error {
	for _, r := range c.rates() {
		if err := r.validate(class); err != nil {
			return err
		}
	}
	for _, n := range []int{c.MaxPending, c.MaxRegistrations, c.MaxRegistrationsClass,
		c.MaxSplices, c.MaxSplicesClass, c.TargetMaxPendingRequests} {
		if n < 0 {
			return fmt.Errorf("ccbserver: class %s: limits must not be negative", class)
		}
	}
	if c.SourcePrefixV4 < 0 || c.SourcePrefixV4 > 32 {
		return fmt.Errorf("ccbserver: class %s: IPv4 source prefix %d is not 0-32", class, c.SourcePrefixV4)
	}
	if c.SourcePrefixV6 < 0 || c.SourcePrefixV6 > 128 {
		return fmt.Errorf("ccbserver: class %s: IPv6 source prefix %d is not 0-128", class, c.SourcePrefixV6)
	}
	return nil
}

func (c *ClassLimits) rates() []Rate {
	return []Rate{c.Connect, c.ConnectClass, c.Register, c.RegisterClass, c.Request, c.RequestClass,
		c.ProxyConnect, c.ProxyConnectClass, c.Bandwidth, c.BandwidthClass, c.BandwidthSplice,
		c.TargetRequest, c.TargetMessage}
}

func (r Rate) validate(class string) error {
	if r.PerSecond < 0 || math.IsNaN(r.PerSecond) || math.IsInf(r.PerSecond, 0) || r.Burst < 0 {
		return fmt.Errorf("ccbserver: class %s: a rate must be a finite non-negative number", class)
	}
	return nil
}

// prefixBits returns the masks that make an address a source key.
func (c *ClassLimits) prefixBits() (v4, v6 int) {
	v4, v6 = c.SourcePrefixV4, c.SourcePrefixV6
	if v4 == 0 {
		v4 = 32
	}
	if v6 == 0 {
		v6 = 64
	}
	return v4, v6
}

// Describe renders the policy for a startup log, one line per class.
func (l *Limits) Describe() []string {
	lines := []string{"default: " + l.Default.describe()}
	for _, c := range l.Classes {
		nets := make([]string, len(c.Networks))
		for i, n := range c.Networks {
			nets[i] = n.String()
		}
		lines = append(lines, fmt.Sprintf("%s (%s): %s", c.Name, strings.Join(nets, ","), c.Limits.describe()))
	}
	t := l.Total
	lines = append(lines, "total: "+joinParts(
		rateText("connect", t.Connect, false), rateText("register", t.Register, false),
		rateText("request", t.Request, false), rateText("proxy_connect", t.ProxyConnect, false),
		capText("registrations", t.MaxRegistrations), capText("splices", t.MaxSplices),
		rateText("bandwidth", t.Bandwidth, true)))
	return lines
}

func (c *ClassLimits) describe() string {
	v4, v6 := c.prefixBits()
	return joinParts(
		rateText("connect", c.Connect, false), rateText("connect/class", c.ConnectClass, false),
		rateText("register", c.Register, false), rateText("register/class", c.RegisterClass, false),
		rateText("request", c.Request, false), rateText("request/class", c.RequestClass, false),
		rateText("proxy_connect", c.ProxyConnect, false), rateText("proxy_connect/class", c.ProxyConnectClass, false),
		capText("pending", c.MaxPending),
		capText("registrations", c.MaxRegistrations), capText("registrations/class", c.MaxRegistrationsClass),
		capText("splices", c.MaxSplices), capText("splices/class", c.MaxSplicesClass),
		rateText("bandwidth", c.Bandwidth, true), rateText("bandwidth/class", c.BandwidthClass, true),
		rateText("bandwidth/splice", c.BandwidthSplice, true),
		rateText("target_request", c.TargetRequest, false), capText("target_pending", c.TargetMaxPendingRequests),
		rateText("target_message", c.TargetMessage, false),
		fmt.Sprintf("source=/%d,/%d", v4, v6))
}

func rateText(name string, r Rate, bytes bool) string {
	if !r.Limited() {
		return ""
	}
	if bytes {
		return fmt.Sprintf("%s=%s/s burst %s", name, byteText(r.PerSecond), byteText(float64(r.byteBurst())))
	}
	return fmt.Sprintf("%s=%g/s burst %d", name, r.PerSecond, r.opBurst())
}

func capText(name string, n int) string {
	if n <= 0 {
		return ""
	}
	return fmt.Sprintf("%s<=%d", name, n)
}

func byteText(b float64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.4gG", b/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.4gM", b/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.4gK", b/(1<<10))
	default:
		return fmt.Sprintf("%.4g", b)
	}
}

func joinParts(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return "unlimited"
	}
	return strings.Join(out, " ")
}
