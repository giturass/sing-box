package dns_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	boxDNS "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/experimental/httpdebug"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type bBoxIntegrationDNSOutbound struct {
	address string
	access  sync.Mutex
	network []string
}

func (o *bBoxIntegrationDNSOutbound) Type() string           { return "direct" }
func (o *bBoxIntegrationDNSOutbound) Tag() string            { return "selected-default" }
func (o *bBoxIntegrationDNSOutbound) Network() []string      { return []string{"tcp", "udp"} }
func (o *bBoxIntegrationDNSOutbound) Dependencies() []string { return nil }
func (o *bBoxIntegrationDNSOutbound) IsEmpty() bool          { return true }
func (o *bBoxIntegrationDNSOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if destination != M.ParseSocksaddr("192.0.2.53:53") {
		return nil, errors.New("DNS script changed the requested upstream")
	}
	if !httpdebug.ScriptEvaluationDisabled(ctx) || !httpdebug.ProcessingDisabled(ctx) {
		return nil, errors.New("DNS script upstream did not prevent recursive evaluation")
	}
	o.access.Lock()
	o.network = append(o.network, network)
	o.access.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, o.address)
}
func (o *bBoxIntegrationDNSOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unexpected packet listener")
}

type bBoxIntegrationDNSOutboundManager struct{ outbound adapter.Outbound }

func (m *bBoxIntegrationDNSOutboundManager) Start(adapter.StartStage, *adapter.Scope) error {
	return nil
}
func (m *bBoxIntegrationDNSOutboundManager) Outbounds() []adapter.Outbound {
	return []adapter.Outbound{m.outbound}
}
func (m *bBoxIntegrationDNSOutboundManager) Default() adapter.Outbound { return m.outbound }
func (m *bBoxIntegrationDNSOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	return m.outbound, m.outbound != nil && m.outbound.Tag() == tag
}
func (m *bBoxIntegrationDNSOutboundManager) Create(context.Context, adapter.Router, log.ContextLogger, string, string, any) error {
	return errors.New("unexpected outbound creation")
}

type bBoxIntegrationDNSFallback struct{ queries atomic.Int32 }

func (*bBoxIntegrationDNSFallback) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (*bBoxIntegrationDNSFallback) Type() string                                   { return "test" }
func (*bBoxIntegrationDNSFallback) Tag() string                                    { return "fallback" }
func (*bBoxIntegrationDNSFallback) Dependencies() []string                         { return nil }
func (*bBoxIntegrationDNSFallback) Reset()                                         {}
func (t *bBoxIntegrationDNSFallback) Exchange(_ context.Context, query *mDNS.Msg) (*mDNS.Msg, error) {
	t.queries.Add(1)
	return boxDNS.FixedResponse(query.Id, query.Question[0], []netip.Addr{netip.MustParseAddr("198.51.100.254")}, 30), nil
}
func (t *bBoxIntegrationDNSFallback) ExchangeAsync(ctx context.Context, query *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	callback(t.Exchange(ctx, query))
}

type bBoxIntegrationDNSManager struct{ fallback adapter.DNSTransport }

func (*bBoxIntegrationDNSManager) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (m *bBoxIntegrationDNSManager) Transports() []adapter.DNSTransport {
	return []adapter.DNSTransport{m.fallback}
}
func (m *bBoxIntegrationDNSManager) Default() adapter.DNSTransport { return m.fallback }
func (*bBoxIntegrationDNSManager) FakeIP() adapter.FakeIPTransport { return nil }
func (m *bBoxIntegrationDNSManager) Transport(tag string) (adapter.DNSTransport, bool) {
	return m.fallback, tag == m.fallback.Tag()
}
func (*bBoxIntegrationDNSManager) Create(context.Context, log.ContextLogger, string, string, any) error {
	return errors.New("script server mutated the DNS manager")
}

func bBoxIntegrationDNSRouter(t *testing.T, outbound adapter.Outbound) (*boxDNS.Router, *adapter.Scope, *bBoxIntegrationDNSFallback) {
	t.Helper()
	registry := boxDNS.NewTransportRegistry()
	transport.RegisterUDP(registry)
	fallback := new(bBoxIntegrationDNSFallback)
	ctx := service.ContextWith[adapter.DNSTransportRegistry](context.Background(), registry)
	ctx = service.ContextWith[adapter.OutboundManager](ctx, &bBoxIntegrationDNSOutboundManager{outbound})
	ctx = service.ContextWith[adapter.DNSTransportManager](ctx, &bBoxIntegrationDNSManager{fallback})
	router, err := boxDNS.NewRouter(ctx, log.NewNOPFactory(), option.DNSOptions{})
	require.NoError(t, err)
	scope := adapter.NewScope(ctx, log.NewNOPFactory().Logger())
	require.NoError(t, router.Start(adapter.StartStateStart, scope))
	t.Cleanup(func() { _ = scope.Close() })
	return router, scope, fallback
}

func bBoxActivateDNSScript(t *testing.T, directory, source string) {
	t.Helper()
	prepared, err := httpdebug.PrepareProcessing(directory, nil, nil, &httpdebug.ScriptsConfig{
		Enabled: true,
		DNS:     []httpdebug.GenericScript{{Name: "resolver", Source: source}},
	}, "", nil, "UTC", httpdebug.ProcessingConfig{
		DNSHosts: []httpdebug.DNSHost{{Pattern: "script.example.test", Script: "resolver"}},
	})
	require.NoError(t, err)
	httpdebug.ActivateProcessing(prepared, nil, nil)
}

type bBoxDNSWireRequest struct {
	network string
	query   *mDNS.Msg
}

func bBoxDNSWireServer(t *testing.T, mode string) (string, <-chan bBoxDNSWireRequest) {
	t.Helper()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	tcp, err := net.Listen("tcp", udp.LocalAddr().String())
	if err != nil {
		_ = udp.Close()
		t.Fatal(err)
	}
	requests := make(chan bBoxDNSWireRequest, 16)
	var calls sync.WaitGroup
	var connectionsAccess sync.Mutex
	connections := make(map[net.Conn]bool)
	calls.Add(2)
	go func() {
		defer calls.Done()
		buffer := make([]byte, 65535)
		for {
			length, client, readErr := udp.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			query := new(mDNS.Msg)
			if query.Unpack(buffer[:length]) != nil {
				continue
			}
			requests <- bBoxDNSWireRequest{"udp", query}
			if mode == "udp-stall" {
				continue
			}
			response := new(mDNS.Msg).SetReply(query)
			response.Truncated = true
			packet, packErr := response.Pack()
			if packErr == nil {
				_, _ = udp.WriteTo(packet, client)
			}
		}
	}()
	go func() {
		defer calls.Done()
		for {
			conn, acceptErr := tcp.Accept()
			if acceptErr != nil {
				return
			}
			connectionsAccess.Lock()
			connections[conn] = true
			connectionsAccess.Unlock()
			calls.Add(1)
			go func() {
				defer calls.Done()
				defer func() {
					_ = conn.Close()
					connectionsAccess.Lock()
					delete(connections, conn)
					connectionsAccess.Unlock()
				}()
				query, readErr := transport.ReadMessage(conn)
				if readErr != nil {
					return
				}
				requests <- bBoxDNSWireRequest{"tcp", query}
				if mode == "tcp-stall" {
					var single [1]byte
					_, _ = conn.Read(single[:])
					return
				}
				response := new(mDNS.Msg).SetReply(query)
				question := query.Question[0]
				response.Answer = []mDNS.RR{&mDNS.A{Hdr: mDNS.RR_Header{Name: question.Name, Rrtype: mDNS.TypeA, Class: question.Qclass, Ttl: 20}, A: net.ParseIP("192.0.2.88")}}
				_ = transport.WriteMessage(conn, response.Id, response)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = tcp.Close()
		_ = udp.Close()
		connectionsAccess.Lock()
		for conn := range connections {
			_ = conn.Close()
		}
		connectionsAccess.Unlock()
		calls.Wait()
	})
	return udp.LocalAddr().String(), requests
}

func TestBBoxDNSScriptRealUDPTruncationUsesSameCoreOutboundForTCP(t *testing.T) {
	address, requests := bBoxDNSWireServer(t, "reply")
	outbound := &bBoxIntegrationDNSOutbound{address: address}
	router, scope, fallback := bBoxIntegrationDNSRouter(t, outbound)
	originalManager := service.FromContext[adapter.OutboundManager](scope.Context())
	bBoxActivateDNSScript(t, t.TempDir(), "$done({server:'192.0.2.53'});")
	t.Cleanup(httpdebug.StopService)
	query := new(mDNS.Msg).SetQuestion("script.example.test.", mDNS.TypeA)
	query.Id = 0x7359
	query.RecursionDesired = false
	query.CheckingDisabled = true
	query.SetEdns0(1232, true)
	response, err := router.Exchange(context.Background(), query, adapter.DNSQueryOptions{Timeout: time.Second})
	require.NoError(t, err)
	require.Equal(t, query.Id, response.Id)
	require.Equal(t, query.Question, response.Question)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.88")}, boxDNS.MessageToAddresses(response))
	for _, network := range []string{"udp", "tcp"} {
		select {
		case request := <-requests:
			require.Equal(t, network, request.network)
			require.Equal(t, query.Question, request.query.Question)
			require.False(t, request.query.RecursionDesired)
			require.True(t, request.query.CheckingDisabled)
			require.NotNil(t, request.query.IsEdns0())
			require.True(t, request.query.IsEdns0().Do())
		case <-time.After(time.Second):
			t.Fatal("expected upstream DNS request was not sent")
		}
	}
	outbound.access.Lock()
	require.Equal(t, []string{"udp", "tcp"}, outbound.network)
	outbound.access.Unlock()
	require.Same(t, originalManager, service.FromContext[adapter.OutboundManager](scope.Context()))
	require.Same(t, outbound, originalManager.Default())
	require.Zero(t, fallback.queries.Load())
}

func TestBBoxDNSScriptRealUDPAndTCPQueriesCancelWithRouter(t *testing.T) {
	for _, mode := range []string{"udp-stall", "tcp-stall"} {
		t.Run(mode, func(t *testing.T) {
			address, requests := bBoxDNSWireServer(t, mode)
			router, scope, fallback := bBoxIntegrationDNSRouter(t, &bBoxIntegrationDNSOutbound{address: address})
			bBoxActivateDNSScript(t, t.TempDir(), "$done({server:'192.0.2.53'});")
			t.Cleanup(httpdebug.StopService)
			query := new(mDNS.Msg).SetQuestion("script.example.test.", mDNS.TypeA)
			completed := make(chan error, 1)
			router.ExchangeAsync(context.Background(), query, adapter.DNSQueryOptions{Timeout: 5 * time.Second}, func(response *mDNS.Msg, err error) { completed <- err })
			wantedNetwork := "udp"
			if mode == "tcp-stall" {
				wantedNetwork = "tcp"
			}
			for {
				select {
				case request := <-requests:
					if request.network != wantedNetwork {
						continue
					}
				case <-time.After(time.Second):
					t.Fatal("the stalled DNS query did not reach the server")
				}
				break
			}
			closed := make(chan error, 1)
			go func() { closed <- scope.Close() }()
			select {
			case err := <-completed:
				require.ErrorIs(t, err, context.Canceled)
			case <-time.After(time.Second):
				t.Fatal("DNS script upstream ignored service cancellation")
			}
			select {
			case err := <-closed:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("DNS router did not wait for and release its script upstream")
			}
			require.Zero(t, fallback.queries.Load())
		})
	}
}

func TestBBoxDNSScriptCacheSpansExchangeAndLookupButNotProfiles(t *testing.T) {
	router, _, fallback := bBoxIntegrationDNSRouter(t, nil)
	directory := t.TempDir()
	bBoxActivateDNSScript(t, directory, `var n=Number($persistentStore.read('dns-count')||'0')+1; $persistentStore.write(String(n),'dns-count'); $done({addresses:['192.0.2.'+n,'2001:db8::'+n],ttl:600});`)
	t.Cleanup(httpdebug.StopService)
	query := new(mDNS.Msg).SetQuestion("script.example.test.", mDNS.TypeA)
	response, err := router.Exchange(context.Background(), query, adapter.DNSQueryOptions{})
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, boxDNS.MessageToAddresses(response))
	addresses, err := router.Lookup(context.Background(), "script.example.test", adapter.DNSQueryOptions{LookupStrategy: C.DomainStrategyIPv6Only})
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("2001:db8::1")}, addresses)
	response, err = router.Exchange(context.Background(), query, adapter.DNSQueryOptions{DisableCache: true})
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.2")}, boxDNS.MessageToAddresses(response))
	httpdebug.ClearScriptDNSCache()
	response, err = router.Exchange(context.Background(), query, adapter.DNSQueryOptions{})
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.3")}, boxDNS.MessageToAddresses(response))
	bBoxActivateDNSScript(t, directory, "$done({address:'198.51.100.55',ttl:600});")
	response, err = router.Exchange(context.Background(), query, adapter.DNSQueryOptions{})
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("198.51.100.55")}, boxDNS.MessageToAddresses(response))
	require.Zero(t, fallback.queries.Load())
}

func TestBBoxDNSScriptWithoutTTLDoesNotCache(t *testing.T) {
	router, _, fallback := bBoxIntegrationDNSRouter(t, nil)
	bBoxActivateDNSScript(t, t.TempDir(), `var n=Number($persistentStore.read('dns-count')||'0')+1; $persistentStore.write(String(n),'dns-count'); $done({address:'192.0.2.'+n});`)
	t.Cleanup(httpdebug.StopService)
	query := new(mDNS.Msg).SetQuestion("script.example.test.", mDNS.TypeA)
	for i := 1; i <= 2; i++ {
		response, err := router.Exchange(context.Background(), query, adapter.DNSQueryOptions{})
		require.NoError(t, err)
		require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2." + strconv.Itoa(i))}, boxDNS.MessageToAddresses(response))
		require.Zero(t, response.Answer[0].Header().Ttl)
	}
	require.Zero(t, fallback.queries.Load())
}
