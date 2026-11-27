package ccbserver

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/bbockelm/golang-ccb/transport/carrier"
)

// defaultClassName labels sources in no configured class.
const defaultClassName = "DEFAULT"

// limitKind names what a bucket or counter limits.
type limitKind string

const (
	kindConnect      limitKind = "connect"
	kindRegister     limitKind = "register"
	kindRequest      limitKind = "request"
	kindProxyConnect limitKind = "proxy_connect"
	kindBandwidth    limitKind = "bandwidth"

	kindPending       limitKind = "pending connections"
	kindRegistrations limitKind = "registrations"
	kindSplices       limitKind = "relayed connections"
)

// limitScope says whose bucket or counter a limit draws on.
type limitScope int

const (
	scopeSource limitScope = iota
	scopeClass
	scopeTotal
)

func (s limitScope) String() string {
	switch s {
	case scopeSource:
		return "per-source"
	case scopeClass:
		return "per-class"
	default:
		return "broker-wide"
	}
}

// overflowSource is the shared source key for sources beyond MaxTrackedSources.
const overflowSource = "overflow"

// LimitError reports an operation refused by a rate limit or a cap.
type LimitError struct {
	What   string // e.g. "request", "registrations"
	Scope  string // "per-source", "per-class", "broker-wide", "per-target"
	Class  string
	Source string
	Limit  string // the limit, rendered
}

func (e *LimitError) Error() string {
	from := ""
	if e.Source != "" {
		from = " from " + e.Source
	}
	class := ""
	if e.Class != "" {
		class = " (class " + e.Class + ")"
	}
	return fmt.Sprintf("rate limited: %s%s%s is over its %s limit of %s", e.What, from, class, e.Scope, e.Limit)
}

// endpoint is one end of an operation, as the limits see it.
type endpoint struct {
	addr netip.Addr // invalid when the peer has no IP (a carrier stream, say)
	// noSource counts the endpoint against its class and the total but not a
	// per-source bucket. A connection arriving over a carrier is one: its
	// address is the carrier's, which fronts a whole cluster, so a per-source
	// limit sized for one host would throttle all of it.
	noSource bool
	// exempt counts the endpoint against nothing.
	exempt bool
}

// compiledClass is a NetworkClass ready to match.
type compiledClass struct {
	name string
	nets []netip.Prefix
	lim  ClassLimits
}

// policy is an immutable snapshot of Limits.
type policy struct {
	limits  Limits
	def     *compiledClass
	classes []*compiledClass
}

func compilePolicy(l Limits) (*policy, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}
	p := &policy{limits: l, def: &compiledClass{name: defaultClassName, lim: l.Default}}
	for _, c := range l.Classes {
		nets := make([]netip.Prefix, len(c.Networks))
		for i, n := range c.Networks {
			nets[i] = n.Masked()
		}
		p.classes = append(p.classes, &compiledClass{name: c.Name, nets: nets, lim: c.Limits})
	}
	return p, nil
}

// classify returns the class whose most specific network contains a.
func (p *policy) classify(a netip.Addr) *compiledClass {
	if !a.IsValid() {
		return p.def
	}
	best, bestBits := p.def, -1
	for _, c := range p.classes {
		for _, n := range c.nets {
			if n.Addr().Is4() != a.Is4() {
				continue
			}
			if n.Bits() > bestBits && n.Contains(a) {
				best, bestBits = c, n.Bits()
			}
		}
	}
	return best
}

// sourceKey is the address masked to the class's source prefix.
func sourceKey(c *compiledClass, a netip.Addr) string {
	v4, v6 := c.lim.prefixBits()
	bits := v6
	if a.Is4() {
		bits = v4
	}
	if bits == a.BitLen() {
		return a.String()
	}
	return netip.PrefixFrom(a, bits).Masked().String()
}

type bucketKey struct {
	kind   limitKind
	scope  limitScope
	class  string
	source string
}

type bucket struct {
	lim  *rate.Limiter
	rate Rate
	key  bucketKey
}

type countKey struct {
	kind   limitKind
	scope  limitScope
	class  string
	source string
}

// limiter enforces a Limits policy.
type limiter struct {
	log *slog.Logger

	mu      sync.Mutex
	pol     *policy
	buckets map[bucketKey]*bucket
	tracked map[limitKind]int // source-scope buckets per kind
	counts  map[countKey]int

	// trusted holds connections the broker opened itself and then serves as
	// commands (reverse connects through its own upstream registration). They
	// are not a remote party's traffic and count against nothing.
	trusted sync.Map // net.Conn -> struct{}

	refusals refusalLog
}

func newLimiter(l Limits, log *slog.Logger) (*limiter, error) {
	p, err := compilePolicy(l)
	if err != nil {
		return nil, err
	}
	lm := &limiter{
		log:     log,
		pol:     p,
		buckets: map[bucketKey]*bucket{},
		tracked: map[limitKind]int{},
		counts:  map[countKey]int{},
	}
	lm.refusals.log = log
	return lm, nil
}

// setPolicy installs a new policy. Buckets restart full; counts of what is
// held (registrations, splices, pending connections) carry over, so a cap
// lowered by a reconfig applies to what already exists.
func (l *limiter) setPolicy(p *policy) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pol = p
	l.buckets = map[bucketKey]*bucket{}
	l.tracked = map[limitKind]int{}
}

func (l *limiter) policy() *policy {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pol
}

// trust exempts conn from every limit until untrust.
func (l *limiter) trust(conn net.Conn)   { l.trusted.Store(conn, struct{}{}) }
func (l *limiter) untrust(conn net.Conn) { l.trusted.Delete(conn) }

// endpointOf describes the peer at the far end of conn.
func (l *limiter) endpointOf(conn net.Conn) endpoint {
	if conn == nil {
		return endpoint{exempt: true}
	}
	if _, ok := l.trusted.Load(conn); ok {
		return endpoint{exempt: true}
	}
	ep := l.endpointFor(conn.RemoteAddr())
	if _, ok := carrier.PipeIDOf(conn); ok {
		ep.noSource = true
	}
	return ep
}

// endpointFor describes the peer at addr.
func (l *limiter) endpointFor(addr net.Addr) endpoint {
	if addr == nil {
		return endpoint{noSource: true}
	}
	return l.endpointForString(addr.String())
}

func (l *limiter) endpointForString(s string) endpoint {
	var a netip.Addr
	if ap, err := netip.ParseAddrPort(s); err == nil {
		a = ap.Addr()
	} else if pa, err := netip.ParseAddr(s); err == nil {
		a = pa
	}
	a = a.Unmap().WithZone("")
	if !a.IsValid() {
		return endpoint{noSource: true}
	}
	if a.IsLoopback() && !l.policy().limits.LimitLoopback {
		return endpoint{addr: a, exempt: true}
	}
	return endpoint{addr: a}
}

// rateFor returns the rate a class sets for kind at scope.
func rateFor(lim *ClassLimits, kind limitKind, scope limitScope) Rate {
	src := scope == scopeSource
	switch kind {
	case kindConnect:
		return pick(src, lim.Connect, lim.ConnectClass)
	case kindRegister:
		return pick(src, lim.Register, lim.RegisterClass)
	case kindRequest:
		return pick(src, lim.Request, lim.RequestClass)
	case kindProxyConnect:
		return pick(src, lim.ProxyConnect, lim.ProxyConnectClass)
	case kindBandwidth:
		return pick(src, lim.Bandwidth, lim.BandwidthClass)
	}
	return Rate{}
}

func pick(source bool, perSource, perClass Rate) Rate {
	if source {
		return perSource
	}
	return perClass
}

func totalRate(t *TotalLimits, kind limitKind) Rate {
	switch kind {
	case kindConnect:
		return t.Connect
	case kindRegister:
		return t.Register
	case kindRequest:
		return t.Request
	case kindProxyConnect:
		return t.ProxyConnect
	case kindBandwidth:
		return t.Bandwidth
	}
	return Rate{}
}

// bucketsFor returns the buckets an operation of kind by eps draws on,
// creating them as needed. The caller holds l.mu.
func (l *limiter) bucketsFor(kind limitKind, eps []endpoint) []*bucket {
	p := l.pol
	var out []*bucket
	seen := map[bucketKey]bool{}
	add := func(k bucketKey, r Rate) {
		if !r.Limited() || seen[k] {
			return
		}
		seen[k] = true
		out = append(out, l.bucket(k, r))
	}
	anyCounted := false
	for _, ep := range eps {
		if ep.exempt {
			continue
		}
		anyCounted = true
		c := p.classify(ep.addr)
		if !ep.noSource && ep.addr.IsValid() {
			if r := rateFor(&c.lim, kind, scopeSource); r.Limited() {
				add(l.sourceBucketKey(kind, c, ep.addr), r)
			}
		}
		add(bucketKey{kind: kind, scope: scopeClass, class: c.name}, rateFor(&c.lim, kind, scopeClass))
	}
	if anyCounted {
		add(bucketKey{kind: kind, scope: scopeTotal}, totalRate(&p.limits.Total, kind))
	}
	return out
}

// sourceBucketKey keys a per-source bucket, folding sources beyond
// MaxTrackedSources into one overflow bucket per class.
func (l *limiter) sourceBucketKey(kind limitKind, c *compiledClass, a netip.Addr) bucketKey {
	k := bucketKey{kind: kind, scope: scopeSource, class: c.name, source: sourceKey(c, a)}
	if _, ok := l.buckets[k]; ok {
		return k
	}
	maxTracked := l.pol.limits.MaxTrackedSources
	if maxTracked <= 0 {
		maxTracked = DefaultMaxTrackedSources
	}
	if l.tracked[kind] >= maxTracked {
		k.source = overflowSource
	}
	return k
}

func (l *limiter) bucket(k bucketKey, r Rate) *bucket {
	if b, ok := l.buckets[k]; ok {
		return b
	}
	burst := r.opBurst()
	if k.kind == kindBandwidth {
		burst = r.byteBurst()
	}
	b := &bucket{lim: rate.NewLimiter(rate.Limit(r.PerSecond), burst), rate: r, key: k}
	l.buckets[k] = b
	if k.scope == scopeSource {
		l.tracked[k.kind]++
	}
	return b
}

// take admits one operation of kind by eps, queueing up to maxWait for a
// token. It returns a *LimitError when the operation would have to wait
// longer, or ctx's error if ctx ends while it waits.
func (l *limiter) take(ctx context.Context, kind limitKind, maxWait time.Duration, eps ...endpoint) error {
	l.mu.Lock()
	bs := l.bucketsFor(kind, eps)
	l.mu.Unlock()
	if len(bs) == 0 {
		return nil
	}
	now := time.Now()
	rs := make([]*rate.Reservation, 0, len(bs))
	cancelAll := func() {
		for _, r := range rs {
			r.CancelAt(now)
		}
	}
	var delay time.Duration
	var worst *bucket
	for _, b := range bs {
		r := b.lim.ReserveN(now, 1)
		if !r.OK() {
			cancelAll()
			return l.refuse(kind, b, eps)
		}
		rs = append(rs, r)
		if d := r.DelayFrom(now); d > delay || worst == nil {
			delay, worst = max(d, delay), b
		}
	}
	if delay > maxWait {
		cancelAll()
		return l.refuse(kind, worst, eps)
	}
	if delay <= 0 {
		return nil
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		cancelAll()
		return ctx.Err()
	}
}

func (l *limiter) refuse(kind limitKind, b *bucket, eps []endpoint) *LimitError {
	e := &LimitError{
		What:   string(kind),
		Scope:  b.key.scope.String(),
		Class:  b.key.class,
		Source: b.key.source,
		Limit:  fmt.Sprintf("%g/s burst %d", b.rate.PerSecond, b.lim.Burst()),
	}
	if e.Source == "" {
		e.Source = firstSource(eps)
	}
	l.refusals.note(e)
	return e
}

func firstSource(eps []endpoint) string {
	for _, ep := range eps {
		if !ep.exempt && ep.addr.IsValid() {
			return ep.addr.String()
		}
	}
	return ""
}

// capFor returns a class's cap on kind at scope.
func capFor(lim *ClassLimits, kind limitKind, scope limitScope) int {
	switch kind {
	case kindPending:
		if scope == scopeSource {
			return lim.MaxPending
		}
	case kindRegistrations:
		if scope == scopeSource {
			return lim.MaxRegistrations
		}
		return lim.MaxRegistrationsClass
	case kindSplices:
		if scope == scopeSource {
			return lim.MaxSplices
		}
		return lim.MaxSplicesClass
	}
	return 0
}

func totalCap(t *TotalLimits, kind limitKind) int {
	switch kind {
	case kindRegistrations:
		return t.MaxRegistrations
	case kindSplices:
		return t.MaxSplices
	}
	return 0
}

// acquire takes one of kind for eps against every cap that applies, or
// refuses with a *LimitError. Everything held is counted whether or not a
// cap is set, so a cap added by a reconfig sees what already exists. The
// returned release is safe to call more than once.
func (l *limiter) acquire(kind limitKind, eps ...endpoint) (func(), error) {
	l.mu.Lock()
	p := l.pol
	type held struct {
		key countKey
		cap int
	}
	var keys []held
	seen := map[countKey]bool{}
	add := func(k countKey, c int) {
		if seen[k] {
			return
		}
		seen[k] = true
		keys = append(keys, held{k, c})
	}
	anyCounted := false
	for _, ep := range eps {
		if ep.exempt {
			continue
		}
		anyCounted = true
		c := p.classify(ep.addr)
		if !ep.noSource && ep.addr.IsValid() {
			add(countKey{kind: kind, scope: scopeSource, class: c.name, source: sourceKey(c, ep.addr)},
				capFor(&c.lim, kind, scopeSource))
		}
		if kind != kindPending {
			add(countKey{kind: kind, scope: scopeClass, class: c.name}, capFor(&c.lim, kind, scopeClass))
		}
	}
	if anyCounted && kind != kindPending {
		add(countKey{kind: kind, scope: scopeTotal}, totalCap(&p.limits.Total, kind))
	}
	for _, h := range keys {
		if h.cap > 0 && l.counts[h.key] >= h.cap {
			l.mu.Unlock()
			e := &LimitError{
				What:   string(kind),
				Scope:  h.key.scope.String(),
				Class:  h.key.class,
				Source: h.key.source,
				Limit:  fmt.Sprintf("%d at once", h.cap),
			}
			if e.Source == "" {
				e.Source = firstSource(eps)
			}
			l.refusals.note(e)
			return func() {}, e
		}
	}
	for _, h := range keys {
		l.counts[h.key]++
	}
	l.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			for _, h := range keys {
				if n := l.counts[h.key] - 1; n > 0 {
					l.counts[h.key] = n
				} else {
					delete(l.counts, h.key)
				}
			}
		})
	}, nil
}

// admitConn is the cedar server's AdmitConnection: it bounds how often a
// source may connect and how many of its connections may be mid-handshake.
func (l *limiter) admitConn(conn net.Conn) (func(), error) {
	ep := l.endpointOf(conn)
	if ep.exempt {
		return nil, nil
	}
	release, err := l.acquire(kindPending, ep)
	if err != nil {
		return nil, err
	}
	if err := l.take(context.Background(), kindConnect, 0, ep); err != nil {
		release()
		return nil, err
	}
	return release, nil
}

// bandwidthFor returns the bandwidth buckets a splice between eps draws on,
// plus a fresh per-splice bucket when the classes set one (the strictest of
// the two ends' per-splice rates).
func (l *limiter) bandwidthFor(eps ...endpoint) []*rate.Limiter {
	l.mu.Lock()
	bs := l.bucketsFor(kindBandwidth, eps)
	p := l.pol
	l.mu.Unlock()
	out := make([]*rate.Limiter, 0, len(bs)+1)
	for _, b := range bs {
		out = append(out, b.lim)
	}
	var splice Rate
	for _, ep := range eps {
		if ep.exempt {
			continue
		}
		r := p.classify(ep.addr).lim.BandwidthSplice
		if r.Limited() && (!splice.Limited() || r.PerSecond < splice.PerSecond) {
			splice = r
		}
	}
	if splice.Limited() {
		out = append(out, rate.NewLimiter(rate.Limit(splice.PerSecond), splice.byteBurst()))
	}
	return out
}

// targetLimits are the limits on one registered daemon.
type targetLimits struct {
	request    *rate.Limiter // nil: unlimited
	message    *rate.Limiter // nil: unlimited
	maxPending int
	class      string
	reqRate    Rate
}

func (l *limiter) targetLimitsFor(ep endpoint) *targetLimits {
	if ep.exempt {
		return &targetLimits{}
	}
	c := l.policy().classify(ep.addr)
	tl := &targetLimits{maxPending: c.lim.TargetMaxPendingRequests, class: c.name, reqRate: c.lim.TargetRequest}
	if r := c.lim.TargetRequest; r.Limited() {
		tl.request = rate.NewLimiter(rate.Limit(r.PerSecond), r.opBurst())
	}
	if r := c.lim.TargetMessage; r.Limited() {
		tl.message = rate.NewLimiter(rate.Limit(r.PerSecond), r.opBurst())
	}
	return tl
}

// takeTargetRequest admits one request to a registered daemon, queueing up to
// maxWait.
func (l *limiter) takeTargetRequest(ctx context.Context, tl *targetLimits, ccbid uint64, maxWait time.Duration) error {
	if tl == nil || tl.request == nil {
		return nil
	}
	now := time.Now()
	r := tl.request.ReserveN(now, 1)
	d := r.DelayFrom(now)
	if !r.OK() || d > maxWait {
		r.CancelAt(now)
		e := &LimitError{
			What:   "request",
			Scope:  "per-target",
			Class:  tl.class,
			Source: fmt.Sprintf("ccbid %d", ccbid),
			Limit:  fmt.Sprintf("%g/s burst %d", tl.reqRate.PerSecond, tl.request.Burst()),
		}
		l.refusals.note(e)
		return e
	}
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		r.CancelAt(now)
		return ctx.Err()
	}
}

// sweep drops per-source buckets that have refilled: a full bucket behaves
// exactly like a new one, so forgetting it changes nothing but memory.
func (l *limiter) sweep(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if k.scope != scopeSource {
			continue
		}
		if b.lim.TokensAt(now) >= float64(b.lim.Burst()) {
			delete(l.buckets, k)
			l.tracked[k.kind]--
		}
	}
}

// run sweeps buckets and summarises refusals until ctx ends.
func (l *limiter) run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			l.sweep(now)
			l.refusals.flush()
		}
	}
}

// refusalLog keeps refusals from flooding the log. The first refusal of a
// kind in a class is logged as it happens; the rest are counted and
// summarised, with the busiest sources, on each flush.
type refusalLog struct {
	log *slog.Logger
	mu  sync.Mutex
	agg map[string]*refusalAgg
}

type refusalAgg struct {
	first   *LimitError
	count   int
	sources map[string]int
}

// maxSummarisedSources bounds the per-source tally kept between flushes.
const maxSummarisedSources = 256

func (r *refusalLog) note(e *LimitError) {
	if r.log == nil {
		return
	}
	key := e.What + "|" + e.Scope + "|" + e.Class
	r.mu.Lock()
	if r.agg == nil {
		r.agg = map[string]*refusalAgg{}
	}
	a, ok := r.agg[key]
	if !ok {
		a = &refusalAgg{first: e, sources: map[string]int{}}
		r.agg[key] = a
	}
	a.count++
	if _, tracked := a.sources[e.Source]; tracked || len(a.sources) < maxSummarisedSources {
		a.sources[e.Source]++
	}
	r.mu.Unlock()
	if !ok {
		r.log.Warn("rate limit refusing", "what", e.What, "scope", e.Scope, "class", e.Class,
			"source", e.Source, "limit", e.Limit, "note", "further refusals are summarised periodically")
	}
}

func (r *refusalLog) flush() {
	r.mu.Lock()
	agg := r.agg
	r.agg = nil
	r.mu.Unlock()
	for _, a := range agg {
		if a.count <= 1 {
			continue
		}
		type sc struct {
			s string
			n int
		}
		var top []sc
		for s, n := range a.sources {
			top = append(top, sc{s, n})
		}
		sort.Slice(top, func(i, j int) bool { return top[i].n > top[j].n || (top[i].n == top[j].n && top[i].s < top[j].s) })
		var parts []string
		for i, t := range top {
			if i == 5 {
				break
			}
			parts = append(parts, fmt.Sprintf("%s=%d", t.s, t.n))
		}
		r.log.Warn("rate limit refusals", "what", a.first.What, "scope", a.first.Scope, "class", a.first.Class,
			"limit", a.first.Limit, "refused", a.count, "sources", len(a.sources), "top", strings.Join(parts, " "))
	}
}

// throttledReader paces reads from r through every limiter in lims. A read
// is capped at chunk bytes, no more than the smallest bucket, so WaitN can
// always be satisfied.
type throttledReader struct {
	ctx   context.Context
	r     io.Reader
	lims  []*rate.Limiter
	chunk int
}

func newThrottledReader(ctx context.Context, r io.Reader, lims []*rate.Limiter) io.Reader {
	if len(lims) == 0 {
		return r
	}
	chunk := 32 << 10
	for _, l := range lims {
		chunk = min(chunk, l.Burst())
	}
	return &throttledReader{ctx: ctx, r: r, lims: lims, chunk: max(chunk, 1)}
}

func (t *throttledReader) Read(p []byte) (int, error) {
	if len(p) > t.chunk {
		p = p[:t.chunk]
	}
	n, err := t.r.Read(p)
	if n > 0 {
		for _, l := range t.lims {
			if werr := l.WaitN(t.ctx, n); werr != nil {
				// The bytes are already read; hand them on and stop.
				return n, werr
			}
		}
	}
	return n, err
}
