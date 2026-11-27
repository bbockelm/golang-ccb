package ccbserver

import (
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// The rate-limit configuration knobs. A knob in classKnobs exists once for
// the default class, as CCB_LIMIT_<SUFFIX>, and once per configured class, as
// CCB_LIMIT_<CLASS>_<SUFFIX>; a class knob left unset takes the default
// class's value. The rest are broker-wide.
//
// Every name is spelled out in full here so that the documentation check
// (docs_knobs_test.go) can see each one is read.
const limitPrefix = "CCB_LIMIT_"

// rateKnob is a _RATE/_BURST pair. bytes marks a bandwidth knob, whose values
// take a size suffix.
type rateKnob struct {
	rate, burst string
	bytes       bool
	field       func(*ClassLimits) *Rate
}

var classRateKnobs = []rateKnob{
	{"CCB_LIMIT_CONNECT_RATE", "CCB_LIMIT_CONNECT_BURST", false, func(c *ClassLimits) *Rate { return &c.Connect }},
	{"CCB_LIMIT_CONNECT_CLASS_RATE", "CCB_LIMIT_CONNECT_CLASS_BURST", false, func(c *ClassLimits) *Rate { return &c.ConnectClass }},
	{"CCB_LIMIT_REGISTER_RATE", "CCB_LIMIT_REGISTER_BURST", false, func(c *ClassLimits) *Rate { return &c.Register }},
	{"CCB_LIMIT_REGISTER_CLASS_RATE", "CCB_LIMIT_REGISTER_CLASS_BURST", false, func(c *ClassLimits) *Rate { return &c.RegisterClass }},
	{"CCB_LIMIT_REQUEST_RATE", "CCB_LIMIT_REQUEST_BURST", false, func(c *ClassLimits) *Rate { return &c.Request }},
	{"CCB_LIMIT_REQUEST_CLASS_RATE", "CCB_LIMIT_REQUEST_CLASS_BURST", false, func(c *ClassLimits) *Rate { return &c.RequestClass }},
	{"CCB_LIMIT_PROXY_CONNECT_RATE", "CCB_LIMIT_PROXY_CONNECT_BURST", false, func(c *ClassLimits) *Rate { return &c.ProxyConnect }},
	{"CCB_LIMIT_PROXY_CONNECT_CLASS_RATE", "CCB_LIMIT_PROXY_CONNECT_CLASS_BURST", false, func(c *ClassLimits) *Rate { return &c.ProxyConnectClass }},
	{"CCB_LIMIT_BANDWIDTH_RATE", "CCB_LIMIT_BANDWIDTH_BURST", true, func(c *ClassLimits) *Rate { return &c.Bandwidth }},
	{"CCB_LIMIT_BANDWIDTH_CLASS_RATE", "CCB_LIMIT_BANDWIDTH_CLASS_BURST", true, func(c *ClassLimits) *Rate { return &c.BandwidthClass }},
	{"CCB_LIMIT_BANDWIDTH_SPLICE_RATE", "CCB_LIMIT_BANDWIDTH_SPLICE_BURST", true, func(c *ClassLimits) *Rate { return &c.BandwidthSplice }},
	{"CCB_LIMIT_TARGET_REQUEST_RATE", "CCB_LIMIT_TARGET_REQUEST_BURST", false, func(c *ClassLimits) *Rate { return &c.TargetRequest }},
	{"CCB_LIMIT_TARGET_MESSAGE_RATE", "CCB_LIMIT_TARGET_MESSAGE_BURST", false, func(c *ClassLimits) *Rate { return &c.TargetMessage }},
}

type intKnob struct {
	name     string
	min, max int
	field    func(*ClassLimits) *int
}

var classIntKnobs = []intKnob{
	{"CCB_LIMIT_MAX_PENDING", 0, math.MaxInt32, func(c *ClassLimits) *int { return &c.MaxPending }},
	{"CCB_LIMIT_MAX_REGISTRATIONS", 0, math.MaxInt32, func(c *ClassLimits) *int { return &c.MaxRegistrations }},
	{"CCB_LIMIT_MAX_REGISTRATIONS_CLASS", 0, math.MaxInt32, func(c *ClassLimits) *int { return &c.MaxRegistrationsClass }},
	{"CCB_LIMIT_MAX_SPLICES", 0, math.MaxInt32, func(c *ClassLimits) *int { return &c.MaxSplices }},
	{"CCB_LIMIT_MAX_SPLICES_CLASS", 0, math.MaxInt32, func(c *ClassLimits) *int { return &c.MaxSplicesClass }},
	{"CCB_LIMIT_TARGET_MAX_PENDING_REQUESTS", 0, math.MaxInt32, func(c *ClassLimits) *int { return &c.TargetMaxPendingRequests }},
	{"CCB_LIMIT_SOURCE_PREFIX_V4", 0, 32, func(c *ClassLimits) *int { return &c.SourcePrefixV4 }},
	{"CCB_LIMIT_SOURCE_PREFIX_V6", 0, 128, func(c *ClassLimits) *int { return &c.SourcePrefixV6 }},
}

// knobClassNetworks names the networks a class covers. It exists only in its
// per-class spelling, CCB_LIMIT_<CLASS>_NETWORKS.
const knobClassNetworks = "CCB_LIMIT_NETWORKS"

// Broker-wide knobs.
const (
	knobEnable            = "CCB_LIMIT_ENABLE"
	knobClasses           = "CCB_LIMIT_CLASSES"
	knobMaxWait           = "CCB_LIMIT_MAX_WAIT"
	knobLoopback          = "CCB_LIMIT_LOOPBACK"
	knobMaxTracked        = "CCB_LIMIT_MAX_TRACKED_SOURCES"
	knobMaxRegistrations  = "CCB_LIMIT_MAX_REGISTRATIONS_TOTAL"
	knobMaxSplicesTotal   = "CCB_LIMIT_MAX_SPLICES_TOTAL"
	knobConnectTotal      = "CCB_LIMIT_CONNECT_TOTAL_RATE"
	knobConnectTotalB     = "CCB_LIMIT_CONNECT_TOTAL_BURST"
	knobRegisterTotal     = "CCB_LIMIT_REGISTER_TOTAL_RATE"
	knobRegisterTotalB    = "CCB_LIMIT_REGISTER_TOTAL_BURST"
	knobRequestTotal      = "CCB_LIMIT_REQUEST_TOTAL_RATE"
	knobRequestTotalB     = "CCB_LIMIT_REQUEST_TOTAL_BURST"
	knobProxyConnectTotal = "CCB_LIMIT_PROXY_CONNECT_TOTAL_RATE"
	knobProxyConnTotalB   = "CCB_LIMIT_PROXY_CONNECT_TOTAL_BURST"
	knobBandwidthTotal    = "CCB_LIMIT_BANDWIDTH_TOTAL_RATE"
	knobBandwidthTotalB   = "CCB_LIMIT_BANDWIDTH_TOTAL_BURST"
)

// MaxSplicesTotalKnob names the knob for Total.MaxSplices, for a daemon that
// derives its own default when it is unset.
const MaxSplicesTotalKnob = knobMaxSplicesTotal

// classKnob renames a default-class knob for class.
func classKnob(name, class string) string {
	return limitPrefix + class + "_" + strings.TrimPrefix(name, limitPrefix)
}

// LimitsFromConfig builds the rate-limit policy from HTCondor configuration,
// starting from DefaultLimits. get looks a knob up. With CCB_LIMIT_ENABLE
// false it returns the zero Limits, which limits nothing.
func LimitsFromConfig(get func(string) (string, bool)) (Limits, error) {
	lookup := func(name string) (string, bool) {
		v, ok := get(name)
		v = strings.TrimSpace(v)
		return v, ok && v != ""
	}
	if v, ok := lookup(knobEnable); ok {
		on, err := parseBool(v)
		if err != nil {
			return Limits{}, fmt.Errorf("%s: %w", knobEnable, err)
		}
		if !on {
			return Limits{}, nil
		}
	}

	l := DefaultLimits()
	if err := applyClassKnobs(lookup, &l.Default, ""); err != nil {
		return Limits{}, err
	}

	if v, ok := lookup(knobMaxWait); ok {
		secs, err := strconv.ParseFloat(v, 64)
		if err != nil || secs < 0 || math.IsInf(secs, 0) || math.IsNaN(secs) {
			return Limits{}, fmt.Errorf("%s: want a number of seconds, not %q", knobMaxWait, v)
		}
		l.MaxWait = time.Duration(secs * float64(time.Second))
	}
	if v, ok := lookup(knobLoopback); ok {
		on, err := parseBool(v)
		if err != nil {
			return Limits{}, fmt.Errorf("%s: %w", knobLoopback, err)
		}
		l.LimitLoopback = on
	}
	for _, k := range []struct {
		name string
		dst  *int
	}{
		{knobMaxTracked, &l.MaxTrackedSources},
		{knobMaxRegistrations, &l.Total.MaxRegistrations},
		{knobMaxSplicesTotal, &l.Total.MaxSplices},
	} {
		if v, ok := lookup(k.name); ok {
			n, err := parseCount(v, 0, math.MaxInt32)
			if err != nil {
				return Limits{}, fmt.Errorf("%s: %w", k.name, err)
			}
			*k.dst = n
		}
	}
	for _, k := range []struct {
		rate, burst string
		bytes       bool
		dst         *Rate
	}{
		{knobConnectTotal, knobConnectTotalB, false, &l.Total.Connect},
		{knobRegisterTotal, knobRegisterTotalB, false, &l.Total.Register},
		{knobRequestTotal, knobRequestTotalB, false, &l.Total.Request},
		{knobProxyConnectTotal, knobProxyConnTotalB, false, &l.Total.ProxyConnect},
		{knobBandwidthTotal, knobBandwidthTotalB, true, &l.Total.Bandwidth},
	} {
		if err := applyRate(lookup, k.rate, k.burst, k.bytes, k.dst); err != nil {
			return Limits{}, err
		}
	}

	if v, ok := lookup(knobClasses); ok {
		names := splitList(v)
		if err := checkClassNames(names); err != nil {
			return Limits{}, err
		}
		for _, name := range names {
			c := NetworkClass{Name: name, Limits: l.Default}
			netKnob := classKnob(knobClassNetworks, name)
			nv, ok := lookup(netKnob)
			if !ok {
				return Limits{}, fmt.Errorf("%s lists class %s, but %s is not set", knobClasses, name, netKnob)
			}
			nets, err := parseNetworks(nv)
			if err != nil {
				return Limits{}, fmt.Errorf("%s: %w", netKnob, err)
			}
			c.Networks = nets
			if err := applyClassKnobs(lookup, &c.Limits, name); err != nil {
				return Limits{}, err
			}
			l.Classes = append(l.Classes, c)
		}
	}
	if err := l.validate(); err != nil {
		return Limits{}, err
	}
	return l, nil
}

// applyClassKnobs overrides dst with the knobs set for class ("" for the
// default class).
func applyClassKnobs(lookup func(string) (string, bool), dst *ClassLimits, class string) error {
	name := func(n string) string {
		if class == "" {
			return n
		}
		return classKnob(n, class)
	}
	for _, k := range classRateKnobs {
		if err := applyRate(lookup, name(k.rate), name(k.burst), k.bytes, k.field(dst)); err != nil {
			return err
		}
	}
	for _, k := range classIntKnobs {
		if v, ok := lookup(name(k.name)); ok {
			n, err := parseCount(v, k.min, k.max)
			if err != nil {
				return fmt.Errorf("%s: %w", name(k.name), err)
			}
			*k.field(dst) = n
		}
	}
	return nil
}

// applyRate reads a _RATE/_BURST pair into dst. A _RATE set without its
// _BURST gets one second's worth of burst, not the burst it replaced: a burst
// sized for one rate is rarely right for another.
func applyRate(lookup func(string) (string, bool), rateName, burstName string, bytes bool, dst *Rate) error {
	rv, rateSet := lookup(rateName)
	bv, burstSet := lookup(burstName)
	if rateSet {
		r, err := parseRate(rv, bytes)
		if err != nil {
			return fmt.Errorf("%s: %w", rateName, err)
		}
		dst.PerSecond = r
		dst.Burst = 0
	}
	if burstSet {
		b, err := parseBurst(bv, bytes)
		if err != nil {
			return fmt.Errorf("%s: %w", burstName, err)
		}
		dst.Burst = b
	}
	return nil
}

// checkClassNames refuses class names that are empty, repeated, or that
// would make some knob name mean two things -- a class called TARGET would
// read CCB_LIMIT_TARGET_REQUEST_RATE as its own REQUEST_RATE.
func checkClassNames(names []string) error {
	owner := map[string]string{}
	claim := func(knob, who string) error {
		if prev, ok := owner[knob]; ok && prev != who {
			return fmt.Errorf("%s: knob %s would belong to both %s and %s; rename the class", knobClasses, knob, prev, who)
		}
		owner[knob] = who
		return nil
	}
	global := []string{knobEnable, knobClasses, knobMaxWait, knobLoopback, knobMaxTracked, knobMaxRegistrations,
		knobMaxSplicesTotal, knobConnectTotal, knobConnectTotalB, knobRegisterTotal, knobRegisterTotalB,
		knobRequestTotal, knobRequestTotalB, knobProxyConnectTotal, knobProxyConnTotalB,
		knobBandwidthTotal, knobBandwidthTotalB}
	classable := classKnobNames()
	for _, k := range append(global, classable...) {
		_ = claim(k, "the default settings")
	}
	seen := map[string]bool{}
	for _, n := range names {
		if !validClassName(n) {
			return fmt.Errorf("%s: class name %q must be letters, digits and underscores", knobClasses, n)
		}
		up := strings.ToUpper(n)
		if seen[up] {
			return fmt.Errorf("%s: class %s is listed twice", knobClasses, n)
		}
		seen[up] = true
		if up == defaultClassName {
			return fmt.Errorf("%s: class name %s is reserved", knobClasses, n)
		}
		who := "class " + n
		for _, k := range append(classable, knobClassNetworks) {
			if err := claim(strings.ToUpper(classKnob(k, n)), who); err != nil {
				return err
			}
		}
	}
	return nil
}

// classKnobNames lists every per-class knob, in its default-class spelling.
func classKnobNames() []string {
	var out []string
	for _, k := range classRateKnobs {
		out = append(out, k.rate, k.burst)
	}
	for _, k := range classIntKnobs {
		out = append(out, k.name)
	}
	return out
}

func validClassName(n string) bool {
	if n == "" {
		return false
	}
	for _, r := range n {
		switch {
		case r == '_', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

// parseNetworks reads a list of CIDR networks or single addresses.
func parseNetworks(v string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range splitList(v) {
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(f); err == nil {
			out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
			continue
		}
		return nil, fmt.Errorf("%q is not a network (want e.g. 192.0.2.0/24 or 2001:db8::/32)", f)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no networks listed")
	}
	return out, nil
}

// parseRate reads operations per second, or for a bandwidth knob bytes per
// second with an optional K, M or G suffix (powers of 1024) and optional
// trailing "B" or "/s".
func parseRate(v string, bytes bool) (float64, error) {
	if bytes {
		n, err := parseSize(v)
		if err != nil {
			return 0, err
		}
		return n, nil
	}
	r, err := strconv.ParseFloat(v, 64)
	if err != nil || r < 0 || math.IsInf(r, 0) || math.IsNaN(r) {
		return 0, fmt.Errorf("want a non-negative number per second, not %q", v)
	}
	return r, nil
}

func parseBurst(v string, bytes bool) (int, error) {
	if bytes {
		n, err := parseSize(v)
		if err != nil {
			return 0, err
		}
		if n > math.MaxInt32 {
			return 0, fmt.Errorf("%q is too large", v)
		}
		return int(n), nil
	}
	return parseCount(v, 0, math.MaxInt32)
}

func parseSize(v string) (float64, error) {
	s := strings.ToUpper(strings.TrimSpace(v))
	s = strings.TrimSuffix(s, "/S")
	s = strings.TrimSuffix(s, "B")
	s = strings.TrimSuffix(s, "I") // KiB, MiB
	mult := 1.0
	switch {
	case strings.HasSuffix(s, "K"):
		mult, s = 1<<10, strings.TrimSuffix(s, "K")
	case strings.HasSuffix(s, "M"):
		mult, s = 1<<20, strings.TrimSuffix(s, "M")
	case strings.HasSuffix(s, "G"):
		mult, s = 1<<30, strings.TrimSuffix(s, "G")
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || n < 0 || math.IsInf(n, 0) || math.IsNaN(n) {
		return 0, fmt.Errorf("want a byte count such as 500K or 10M, not %q", v)
	}
	return n * mult, nil
}

func parseCount(v string, lo, hi int) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("want a whole number from %d to %d, not %q", lo, hi, v)
	}
	return n, nil
}

func parseBool(v string) (bool, error) {
	switch strings.ToLower(v) {
	case "true", "yes", "1", "on", "t", "y":
		return true, nil
	case "false", "no", "0", "off", "f", "n":
		return false, nil
	}
	return false, fmt.Errorf("want true or false, not %q", v)
}

// splitList splits an HTCondor list on commas and whitespace.
func splitList(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
}
