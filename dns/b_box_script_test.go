package dns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/httpdebug"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func bBoxDNSRouterForTest(t *testing.T, resolve func(context.Context, string, ...bool) (httpdebug.DNSScriptResult, bool, error)) (*Router, *fakeDNSTransport) {
	t.Helper()
	final := &fakeDNSTransport{tag: "final", immediate: true, address: netip.MustParseAddr("192.0.2.250")}
	router := raceTestRouter(t, final)
	router.client = NewClient(ClientOptions{Context: router.ctx, Logger: router.logger})
	state := newBBoxScriptDNSState(router.ctx)
	state.match = func(context.Context, string) bool { return true }
	state.resolve = resolve
	router.bBoxScriptDNS = state
	t.Cleanup(func() { _ = state.close() })
	return router, final
}

func bBoxDNSQuestionForTest(queryType, queryClass uint16) *mDNS.Msg {
	query := new(mDNS.Msg).SetQuestion("script.example.test.", queryType)
	query.Id = 0x6a45
	query.Question[0].Qclass = queryClass
	query.RecursionDesired = false
	query.CheckingDisabled = true
	query.AuthenticatedData = true
	query.SetEdns0(1232, true)
	return query
}

func TestBBoxDNSHostExchangeTypesAndFlags(t *testing.T) {
	t.Parallel()
	addresses := []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")}
	for _, legacy := range []bool{false, true} {
		for _, test := range []struct {
			name   string
			qtype  uint16
			qclass uint16
			types  []uint16
		}{
			{"A", mDNS.TypeA, mDNS.ClassINET, []uint16{mDNS.TypeA}},
			{"AAAA", mDNS.TypeAAAA, mDNS.ClassINET, []uint16{mDNS.TypeAAAA}},
			{"ANY", mDNS.TypeANY, mDNS.ClassINET, []uint16{mDNS.TypeA, mDNS.TypeAAAA}},
			{"TXT", mDNS.TypeTXT, mDNS.ClassINET, nil},
			{"CHAOS", mDNS.TypeA, mDNS.ClassCHAOS, nil},
		} {
			t.Run(fmt.Sprintf("legacy=%v/%s", legacy, test.name), func(t *testing.T) {
				var evaluations atomic.Int32
				router, final := bBoxDNSRouterForTest(t, func(ctx context.Context, domain string, disableCache ...bool) (httpdebug.DNSScriptResult, bool, error) {
					evaluations.Add(1)
					if domain != "script.example.test" || len(disableCache) != 1 || disableCache[0] {
						return httpdebug.DNSScriptResult{}, true, errors.New("wrong DNS script input")
					}
					return httpdebug.DNSScriptResult{Addresses: addresses, TTL: 37, TTLSet: true}, true, nil
				})
				router.legacyDNSMode = legacy
				query := bBoxDNSQuestionForTest(test.qtype, test.qclass)
				original := query.Copy()
				// Explicit transports must not bypass the profile's Host mapping.
				response, err := router.Exchange(context.Background(), query, adapter.DNSQueryOptions{Transport: final})
				require.NoError(t, err)
				require.Equal(t, original, query)
				require.Equal(t, query.Id, response.Id)
				require.Equal(t, query.Question, response.Question)
				require.False(t, response.RecursionDesired)
				require.True(t, response.CheckingDisabled)
				require.False(t, response.AuthenticatedData)
				require.True(t, response.Response)
				require.True(t, response.Authoritative)
				require.True(t, response.RecursionAvailable)
				require.Equal(t, mDNS.RcodeSuccess, response.Rcode)
				require.NotNil(t, response.IsEdns0())
				require.True(t, response.IsEdns0().Do())
				var gotTypes []uint16
				for _, answer := range response.Answer {
					gotTypes = append(gotTypes, answer.Header().Rrtype)
					require.Equal(t, uint32(37), answer.Header().Ttl)
					require.Equal(t, query.Question[0].Qclass, answer.Header().Class)
				}
				require.Equal(t, test.types, gotTypes)
				require.Equal(t, int32(1), evaluations.Load())
				require.Zero(t, final.queryCount.Load())
			})
		}
	}
}

func TestBBoxDNSHostTTLCacheOptionsAndAddressValidation(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name         string
		result       httpdebug.DNSScriptResult
		options      adapter.DNSQueryOptions
		disableCache bool
		clientCache  bool
		wantTTL      uint32
		wantError    bool
	}{
		{"without-ttl", httpdebug.DNSScriptResult{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}, adapter.DNSQueryOptions{}, false, false, 0, false},
		{"zero-ttl", httpdebug.DNSScriptResult{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, TTLSet: true}, adapter.DNSQueryOptions{}, false, false, 0, false},
		{"query-disables-cache", httpdebug.DNSScriptResult{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, TTL: 12, TTLSet: true}, adapter.DNSQueryOptions{DisableCache: true}, true, false, 12, false},
		{"client-disables-cache", httpdebug.DNSScriptResult{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, TTL: 12, TTLSet: true}, adapter.DNSQueryOptions{}, true, true, 12, false},
		{"invalid-address", httpdebug.DNSScriptResult{Addresses: []netip.Addr{{}}}, adapter.DNSQueryOptions{}, false, false, 0, true},
		{"zoned-address", httpdebug.DNSScriptResult{Addresses: []netip.Addr{netip.MustParseAddr("fe80::1%test")}}, adapter.DNSQueryOptions{}, false, false, 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			router, final := bBoxDNSRouterForTest(t, func(ctx context.Context, domain string, disableCache ...bool) (httpdebug.DNSScriptResult, bool, error) {
				if len(disableCache) != 1 || disableCache[0] != test.disableCache {
					return httpdebug.DNSScriptResult{}, true, errors.New("cache option was not preserved")
				}
				return test.result, true, nil
			})
			if test.clientCache {
				router.client = NewClient(ClientOptions{Context: router.ctx, Logger: router.logger, DisableCache: true})
			}
			response, err := router.Exchange(context.Background(), bBoxDNSQuestionForTest(mDNS.TypeA, mDNS.ClassINET), test.options)
			if test.wantError {
				require.Error(t, err)
				require.Nil(t, response)
			} else {
				require.NoError(t, err)
				require.Len(t, response.Answer, 1)
				require.Equal(t, test.wantTTL, response.Answer[0].Header().Ttl)
			}
			require.Zero(t, final.queryCount.Load())
		})
	}
}

func TestBBoxDNSHostLookupStrategies(t *testing.T) {
	t.Parallel()
	address4 := netip.MustParseAddr("192.0.2.10")
	address6 := netip.MustParseAddr("2001:db8::10")
	for _, test := range []struct {
		name    string
		options adapter.DNSQueryOptions
		want    []netip.Addr
	}{
		{"default", adapter.DNSQueryOptions{}, []netip.Addr{address4, address6}},
		{"prefer6", adapter.DNSQueryOptions{LookupStrategy: C.DomainStrategyPreferIPv6}, []netip.Addr{address6, address4}},
		{"v4", adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv4Only}, []netip.Addr{address4}},
		{"v6", adapter.DNSQueryOptions{LookupStrategy: C.DomainStrategyIPv6Only}, []netip.Addr{address6}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var evaluations atomic.Int32
			router, final := bBoxDNSRouterForTest(t, func(context.Context, string, ...bool) (httpdebug.DNSScriptResult, bool, error) {
				evaluations.Add(1)
				return httpdebug.DNSScriptResult{Addresses: []netip.Addr{address6, address4}}, true, nil
			})
			addresses, err := router.Lookup(context.Background(), "script.example.test.", test.options)
			require.NoError(t, err)
			require.Equal(t, test.want, addresses)
			require.Equal(t, int32(1), evaluations.Load())
			require.Zero(t, final.queryCount.Load())
		})
	}
}

func TestBBoxDNSHostFailureDoesNotUseStandardDNS(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		result   httpdebug.DNSScriptResult
		matched  bool
		err      error
		fallback bool
	}{
		{"explicit-fallback", httpdebug.DNSScriptResult{Fallback: true}, true, nil, true},
		{"disabled-script", httpdebug.DNSScriptResult{}, false, nil, true},
		{"script-error", httpdebug.DNSScriptResult{}, true, errors.New("script failed"), false},
		{"invalid-result", httpdebug.DNSScriptResult{}, true, nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			router, final := bBoxDNSRouterForTest(t, func(context.Context, string, ...bool) (httpdebug.DNSScriptResult, bool, error) {
				return test.result, test.matched, test.err
			})
			query := bBoxDNSQuestionForTest(mDNS.TypeA, mDNS.ClassINET)
			response, err := router.Exchange(context.Background(), query, adapter.DNSQueryOptions{})
			if test.fallback {
				require.NoError(t, err)
				require.Equal(t, netip.MustParseAddr("192.0.2.250"), responseAddress(t, response))
				require.Equal(t, int32(1), final.queryCount.Load())
			} else {
				require.Error(t, err)
				require.Nil(t, response)
				require.Zero(t, final.queryCount.Load())
			}
		})
	}
}

func TestBBoxDNSHostAsyncAdmissionAndCancellation(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	unwind := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(unwind) })
	router, final := bBoxDNSRouterForTest(t, func(ctx context.Context, domain string, _ ...bool) (httpdebug.DNSScriptResult, bool, error) {
		close(started)
		<-ctx.Done()
		<-unwind
		return httpdebug.DNSScriptResult{}, true, ctx.Err()
	})
	t.Cleanup(unblock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	completed := make(chan error, 1)
	var callbacks atomic.Int32
	router.ExchangeAsync(ctx, bBoxDNSQuestionForTest(mDNS.TypeA, mDNS.ClassINET), adapter.DNSQueryOptions{}, func(response *mDNS.Msg, err error) {
		callbacks.Add(1)
		completed <- err
	})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("asynchronous script evaluation did not start")
	}
	closed := make(chan struct{})
	go func() {
		_ = router.StopScriptDNS()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("DNS Host lifecycle returned before the call unwound")
	case <-time.After(10 * time.Millisecond):
	}
	unblock()
	select {
	case err := <-completed:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("script cancellation did not deliver a callback")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("DNS Host lifecycle did not finish")
	}
	require.Equal(t, int32(1), callbacks.Load())
	require.Zero(t, final.queryCount.Load())
}

func TestBBoxDNSHostUnmatchedAsyncCacheStaysImmediate(t *testing.T) {
	t.Parallel()
	router, final := bBoxDNSRouterForTest(t, func(context.Context, string, ...bool) (httpdebug.DNSScriptResult, bool, error) {
		return httpdebug.DNSScriptResult{}, true, errors.New("unmatched host ran a script")
	})
	router.bBoxScriptDNS.match = func(context.Context, string) bool { return false }
	called := false
	router.ExchangeAsync(context.Background(), bBoxDNSQuestionForTest(mDNS.TypeA, mDNS.ClassINET), adapter.DNSQueryOptions{}, func(response *mDNS.Msg, err error) {
		require.NoError(t, err)
		called = true
	})
	require.True(t, called)
	require.Equal(t, int32(1), final.queryCount.Load())
}

type bBoxDNSOutbound struct{ tag string }

func (o *bBoxDNSOutbound) Type() string           { return "test" }
func (o *bBoxDNSOutbound) Tag() string            { return o.tag }
func (o *bBoxDNSOutbound) Network() []string      { return []string{"tcp", "udp"} }
func (o *bBoxDNSOutbound) Dependencies() []string { return nil }
func (o *bBoxDNSOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("unexpected outbound dial")
}
func (o *bBoxDNSOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unexpected outbound listen")
}

type bBoxDNSOutboundManagerForTest struct{ outbound adapter.Outbound }

func (m *bBoxDNSOutboundManagerForTest) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (m *bBoxDNSOutboundManagerForTest) Outbounds() []adapter.Outbound {
	return []adapter.Outbound{m.outbound}
}
func (m *bBoxDNSOutboundManagerForTest) Default() adapter.Outbound { return m.outbound }
func (m *bBoxDNSOutboundManagerForTest) Outbound(tag string) (adapter.Outbound, bool) {
	return m.outbound, m.outbound != nil && m.outbound.Tag() == tag
}
func (m *bBoxDNSOutboundManagerForTest) Create(context.Context, adapter.Router, log.ContextLogger, string, string, any) error {
	return errors.New("unexpected outbound creation")
}

type bBoxDNSPipeOutbound struct {
	bBoxDNSOutbound
	conn net.Conn
}

func (o *bBoxDNSPipeOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return o.conn, nil
}

func TestBBoxDNSScriptDefaultOutboundConnectionUsesQueryLifetime(t *testing.T) {
	t.Parallel()
	upstream, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	defer cancelLifetime()
	dialCtx, cancelDial := context.WithCancel(lifetime)
	defer cancelDial()
	outbound := &bBoxDefaultDNSOutbound{
		Outbound: &bBoxDNSPipeOutbound{bBoxDNSOutbound: bBoxDNSOutbound{tag: "default"}, conn: upstream},
		lifetime: lifetime,
	}
	conn, err := outbound.DialContext(dialCtx, "udp", M.ParseSocksaddr("192.0.2.53:53"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	// ConnPool cancels this temporary context after successful installation.
	// It must remain possible to send the first query on the live connection.
	cancelDial()
	written := make(chan error, 1)
	go func() { _, writeErr := peer.Write([]byte{1}); written <- writeErr }()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Second)))
	var single [1]byte
	_, err = io.ReadFull(conn, single[:])
	require.NoError(t, err)
	require.Equal(t, byte(1), single[0])
	require.NoError(t, <-written)
	// Service/query cancellation closes even a blocked read immediately.
	cancelLifetime()
	_, err = conn.Read(single[:])
	require.ErrorIs(t, err, io.ErrClosedPipe)
}

type bBoxDNSServerTransport struct {
	TransportAdapter
	server  string
	closed  *atomic.Int32
	queries *atomic.Int32
}

func (t *bBoxDNSServerTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateStart {
		scope.Add(func() error { t.closed.Add(1); return nil })
	}
	return nil
}
func (t *bBoxDNSServerTransport) Reset() {}
func (t *bBoxDNSServerTransport) Exchange(ctx context.Context, query *mDNS.Msg) (*mDNS.Msg, error) {
	t.queries.Add(1)
	if !httpdebug.ScriptEvaluationDisabled(ctx) || !httpdebug.ProcessingDisabled(ctx) {
		return nil, errors.New("DNS server query lost recursion prevention")
	}
	if t.server == "192.0.2.1" {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	response := new(mDNS.Msg).SetReply(query)
	question := query.Question[0]
	switch question.Qtype {
	case mDNS.TypeA:
		response.Answer = []mDNS.RR{&mDNS.A{Hdr: mDNS.RR_Header{Name: question.Name, Rrtype: mDNS.TypeA, Class: question.Qclass, Ttl: 15}, A: net.ParseIP("192.0.2.22")}}
	case mDNS.TypeAAAA:
		response.Answer = []mDNS.RR{&mDNS.AAAA{Hdr: mDNS.RR_Header{Name: question.Name, Rrtype: mDNS.TypeAAAA, Class: question.Qclass, Ttl: 15}, AAAA: net.ParseIP("2001:db8::22")}}
	default:
		response.Answer = []mDNS.RR{&mDNS.TXT{Hdr: mDNS.RR_Header{Name: question.Name, Rrtype: mDNS.TypeTXT, Class: question.Qclass, Ttl: 15}, Txt: []string{"server-choice"}}}
	}
	return response, nil
}
func (t *bBoxDNSServerTransport) ExchangeAsync(ctx context.Context, query *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() { callback(t.Exchange(ctx, query)) }()
}

func TestBBoxDNSScriptServerDelegationAndLookup(t *testing.T) {
	t.Parallel()
	servers := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}
	router, final := bBoxDNSRouterForTest(t, func(context.Context, string, ...bool) (httpdebug.DNSScriptResult, bool, error) {
		return httpdebug.DNSScriptResult{Servers: servers}, true, nil
	})
	registry := NewTransportRegistry()
	var constructed, closed, queries atomic.Int32
	RegisterTransport[option.RemoteDNSServerOptions](registry, C.DNSTypeUDP, func(ctx context.Context, logger log.ContextLogger, tag string, options option.RemoteDNSServerOptions) (adapter.DNSTransport, error) {
		constructed.Add(1)
		if options.Detour != "proxy" || options.ServerPort != 53 || !httpdebug.ScriptEvaluationDisabled(ctx) || !httpdebug.ProcessingDisabled(ctx) {
			return nil, errors.New("script DNS server bypassed core transport settings")
		}
		return &bBoxDNSServerTransport{TransportAdapter: NewTransportAdapter(C.DNSTypeUDP, tag, nil), server: options.Server, closed: &closed, queries: &queries}, nil
	})
	router.outbound = &bBoxDNSOutboundManagerForTest{&bBoxDNSOutbound{"proxy"}}
	router.ctx = service.ContextWith[adapter.DNSTransportRegistry](router.ctx, registry)
	router.ctx = service.ContextWith[adapter.OutboundManager](router.ctx, router.outbound)
	query := bBoxDNSQuestionForTest(mDNS.TypeTXT, mDNS.ClassCHAOS)
	response, err := router.Exchange(context.Background(), query, adapter.DNSQueryOptions{Timeout: time.Second})
	require.NoError(t, err)
	require.Equal(t, query.Id, response.Id)
	require.Equal(t, query.Question, response.Question)
	require.False(t, response.RecursionDesired)
	require.True(t, response.CheckingDisabled)
	require.Len(t, response.Answer, 1)
	require.Equal(t, uint16(mDNS.ClassCHAOS), response.Answer[0].Header().Class)
	require.Equal(t, []string{"server-choice"}, response.Answer[0].(*mDNS.TXT).Txt)
	require.Equal(t, constructed.Load(), closed.Load())
	require.Same(t, router.outbound, service.FromContext[adapter.OutboundManager](router.ctx))
	addresses, err := router.Lookup(context.Background(), "script.example.test", adapter.DNSQueryOptions{LookupStrategy: C.DomainStrategyPreferIPv6, Timeout: time.Second})
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("2001:db8::22"), netip.MustParseAddr("192.0.2.22")}, addresses)
	require.Equal(t, constructed.Load(), closed.Load())
	router.defaultDomainStrategy = C.DomainStrategyIPv4Only
	for _, test := range []struct {
		options adapter.DNSQueryOptions
		want    netip.Addr
	}{
		{adapter.DNSQueryOptions{LookupStrategy: C.DomainStrategyIPv6Only}, netip.MustParseAddr("2001:db8::22")},
		{adapter.DNSQueryOptions{LookupStrategy: C.DomainStrategyIPv6Only, Strategy: C.DomainStrategyIPv4Only}, netip.MustParseAddr("2001:db8::22")},
		{adapter.DNSQueryOptions{LookupStrategy: C.DomainStrategyIPv4Only, Strategy: C.DomainStrategyIPv6Only}, netip.MustParseAddr("192.0.2.22")},
	} {
		test.options.Timeout = time.Second
		addresses, err = router.Lookup(context.Background(), "script.example.test", test.options)
		require.NoError(t, err)
		require.Equal(t, []netip.Addr{test.want}, addresses)
		require.Equal(t, constructed.Load(), closed.Load())
		require.Same(t, router.outbound, service.FromContext[adapter.OutboundManager](router.ctx))
	}
	require.Zero(t, final.queryCount.Load())
	require.GreaterOrEqual(t, queries.Load(), int32(3))
}

func TestBBoxDNSScriptMissingDefaultOutboundFails(t *testing.T) {
	t.Parallel()
	router, final := bBoxDNSRouterForTest(t, func(context.Context, string, ...bool) (httpdebug.DNSScriptResult, bool, error) {
		return httpdebug.DNSScriptResult{Servers: []netip.Addr{netip.MustParseAddr("192.0.2.53")}}, true, nil
	})
	for _, manager := range []adapter.OutboundManager{nil, &bBoxDNSOutboundManagerForTest{}, &bBoxDNSOutboundManagerForTest{&bBoxDNSOutbound{}}} {
		router.outbound = manager
		response, err := router.Exchange(context.Background(), bBoxDNSQuestionForTest(mDNS.TypeA, mDNS.ClassINET), adapter.DNSQueryOptions{})
		require.ErrorContains(t, err, "named default outbound")
		require.Nil(t, response)
	}
	require.Zero(t, final.queryCount.Load())
}

func TestBBoxDNSAddressResponseDoesNotMutateScriptAddresses(t *testing.T) {
	t.Parallel()
	addresses := []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.1")}
	original := append([]netip.Addr(nil), addresses...)
	_, err := bBoxDNSAddressResponse(bBoxDNSQuestionForTest(mDNS.TypeANY, mDNS.ClassINET), httpdebug.DNSScriptResult{Addresses: addresses}, adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv6})
	require.NoError(t, err)
	require.True(t, reflect.DeepEqual(original, addresses))
}
