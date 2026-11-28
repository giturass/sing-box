package route

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/httpdebug"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type requestTestOutboundManager struct {
	adapter.OutboundManager
	list map[string]adapter.Outbound
}

type requestCleanupOutbound struct {
	adapter.Outbound
	opened, entered, release chan struct{}
	physicallyClosed         atomic.Bool
}

func (*requestCleanupOutbound) Tag() string       { return "cleanup" }
func (*requestCleanupOutbound) Type() string      { return "direct" }
func (*requestCleanupOutbound) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }
func (o *requestCleanupOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	close(o.opened)
	return &requestCleanupPacketConn{PacketConn: conn, owner: o}, nil
}

type requestCleanupPacketConn struct {
	net.PacketConn
	owner *requestCleanupOutbound
	once  sync.Once
	err   error
}

func (c *requestCleanupPacketConn) Close() error {
	c.once.Do(func() {
		close(c.owner.entered)
		<-c.owner.release
		c.err = c.PacketConn.Close()
		c.owner.physicallyClosed.Store(true)
	})
	return c.err
}

func TestBboxHTTPDebugRequestDialWaitsForNativePacketSocketCleanup(t *testing.T) {
	outbound := &requestCleanupOutbound{opened: make(chan struct{}), entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(outbound.release) })
	logger := log.NewNOPFactory().NewLogger("request-cleanup")
	router := &Router{ctx: context.Background(), logger: logger,
		outbound:     &requestTestOutboundManager{list: map[string]adapter.Outbound{"A": outbound}},
		dnsTransport: &requestTestDNSManager{}, connection: NewConnectionManager(context.Background(), logger)}
	metadata := adapter.InboundContext{Network: N.NetworkUDP, Source: M.ParseSocksaddr("127.0.0.1:4321"), Destination: M.ParseSocksaddr("127.0.0.1:443"), Domain: "cleanup.test"}
	request, err := http.NewRequest("GET", "https://cleanup.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := router.debugRequestRouter(metadata, "quic")(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, _, err := plan.PacketDial(ctx, "")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { release(); conn.Close(); cancel() })
	select {
	case <-outbound.opened:
	case <-time.After(time.Second):
		t.Fatal("native connection manager did not open the packet socket")
	}
	closed := make(chan struct{})
	go func() { conn.Close(); close(closed) }()
	select {
	case <-outbound.entered:
	case <-time.After(time.Second):
		t.Fatal("request shutdown did not start native UDP cleanup")
	}
	select {
	case <-closed:
		t.Fatal("request route callback completed before physical UDP cleanup")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("request route did not join native UDP cleanup")
	}
	if !outbound.physicallyClosed.Load() {
		t.Fatal("native packet socket survived its request route")
	}
}

func (m *requestTestOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	value, found := m.list[tag]
	return value, found
}
func (m *requestTestOutboundManager) Default() adapter.Outbound { return m.list["A"] }

type requestTestDNSManager struct{ adapter.DNSTransportManager }

func (*requestTestDNSManager) FakeIP() adapter.FakeIPTransport { return nil }

type requestTestOutbound struct {
	adapter.Outbound
	tag  string
	seen chan adapter.InboundContext
	done chan struct{}
}

func (o *requestTestOutbound) Tag() string       { return o.tag }
func (o *requestTestOutbound) Type() string      { return "direct" }
func (o *requestTestOutbound) Network() []string { return []string{N.NetworkTCP} }
func (o *requestTestOutbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	defer onClose(nil)
	defer conn.Close()
	o.seen <- metadata
	request, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return
	}
	request.Body.Close()
	_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n"+o.tag)
	if o.done != nil {
		close(o.done)
	}
}

// Called under the existing capture fixture so every service activation shares
// its one private store, as the actual app lifecycle requires.
func testBboxHTTPRequestRoutingWithNativeRulesAndScript(t *testing.T, directory string) {
	t.Helper()
	scripts := &httpdebug.ScriptsConfig{Enabled: true, Rule: []httpdebug.GenericScript{{Name: "path", Source: `$done({matched: $request.url !== null && /\/script$/.test($request.url)});`}}}
	rewrite := &httpdebug.RewriteConfig{Enabled: true, URLRewrite: []httpdebug.URLRewrite{{RewriteMatch: httpdebug.RewriteMatch{Pattern: `^http://native\.request\.test/(url|ua|script)$`}, Action: "header", Replacement: "http://native.request.test/changed"}}}
	prepared, err := httpdebug.PrepareProcessing(directory, nil, rewrite, scripts, "", nil, "UTC", httpdebug.ProcessingConfig{HTTPRouting: &httpdebug.HTTPRoutingConfig{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	httpdebug.ActivateProcessing(prepared, nil, nil)
	defer httpdebug.StopService()
	if err = httpdebug.Start(directory, `{"ports":[80]}`, "", nil); err != nil {
		t.Fatal(err)
	}
	logger := log.NewNOPFactory().NewLogger("request-router")
	outbounds := make(map[string]adapter.Outbound)
	for _, name := range []string{"A", "B", "C"} {
		outbounds[name] = &requestTestOutbound{tag: name, seen: make(chan adapter.InboundContext, 8)}
	}
	router := &Router{ctx: context.Background(), logger: logger, outbound: &requestTestOutboundManager{list: outbounds}, dnsTransport: &requestTestDNSManager{}}
	for _, options := range []option.DefaultRule{
		{RawDefaultRule: option.RawDefaultRule{HTTPURLRegex: []string{`/url$`}}, RuleAction: option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: "A"}}},
		{RawDefaultRule: option.RawDefaultRule{HTTPUserAgent: []string{"AppB/*"}}, RuleAction: option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: "B"}}},
		{RawDefaultRule: option.RawDefaultRule{Script: "path"}, RuleAction: option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: "C"}}},
		{RuleAction: option.RuleAction{Action: C.RuleActionTypeReject, RejectOptions: option.RejectActionOptions{Method: C.RuleActionRejectMethodDefault, NoDrop: true}}},
	} {
		rule, err := R.NewDefaultRule(context.Background(), logger, options)
		if err != nil {
			t.Fatal(err)
		}
		router.rules = append(router.rules, rule)
	}
	metadata := adapter.InboundContext{Network: "tcp", Inbound: "tun", Protocol: "http", Domain: "native.request.test", Source: M.ParseSocksaddr("192.0.2.2:4321"), Destination: M.ParseSocksaddr("198.51.100.1:80"), RouteOutbound: "connection-only", RouteRule: "connection-rule", ProcessInfo: &adapter.ConnectionOwner{UserId: 1234, PackageNames: []string{"com.native"}}}
	manager := trafficcontrol.NewManager()
	defer manager.CloseAllConnections()
	router.trackers = []adapter.ConnectionTracker{manager}
	// A pending HTTP condition cannot allow a known non-HTTP connection through
	// the final rejection, even while the HTTP engine is running.
	nonHTTP := metadata
	nonHTTP.Protocol = "ssh"
	opaqueClient, opaqueInbound := net.Pipe()
	defer opaqueClient.Close()
	opaqueClosed := make(chan error, 1)
	router.RouteConnectionEx(context.Background(), opaqueInbound, nonHTTP, N.OnceClose(func(err error) { opaqueClosed <- err }))
	if err := <-opaqueClosed; !R.IsRejected(err) {
		t.Fatal("pending request condition bypassed non-HTTP rejection", err)
	}
	if manager.ConnectionsLen() != 0 {
		t.Fatal("non-HTTP rejection entered the request engine")
	}
	// Unknown protocols may enter the configured plaintext parser before they
	// are rejected. Its replay cache and tracked route must close together.
	unknown := metadata
	unknown.Protocol = ""
	unknownClient, unknownInbound := net.Pipe()
	defer unknownClient.Close()
	defer unknownInbound.Close()
	unknownClient.SetDeadline(time.Now().Add(2 * time.Second))
	unknownClosed := make(chan error, 1)
	go router.RouteConnectionEx(context.Background(), unknownInbound, unknown, N.OnceClose(func(err error) { unknownClosed <- err }))
	if _, err = io.WriteString(unknownClient, "BOGUS\r\n\r\n"); err != nil {
		t.Fatal("could not send opaque bytes to pending request parser", err)
	}
	select {
	case err = <-unknownClosed:
		if !R.IsRejected(err) {
			t.Fatal("opaque connection did not retain the final rejection", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("opaque connection rejection did not finish")
	}
	if manager.ConnectionsLen() != 0 || len(manager.ClosedConnections()) != 1 {
		t.Fatal("deferred non-HTTP rejection leaked its tracked connection", manager.Connections())
	}
	client, inbound := net.Pipe()
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	router.RouteConnectionEx(context.Background(), inbound, metadata, nil)
	connections := manager.Connections()
	if len(connections) != 1 {
		t.Fatal("FINAL REJECT prevented HTTP request parsing", connections)
	}
	connectionID := connections[0].ID.String()
	reader := bufio.NewReader(client)
	for _, test := range []struct {
		path, agent, body string
		status            int
	}{{"url", "AppB/1", "A", 200}, {"ua", "AppB/1", "B", 200}, {"script", "Other", "C", 200}, {"reject", "Other", "Request rejected by B-box routing\n", 403}, {"url", "Other", "A", 200}} {
		request, _ := http.NewRequest("GET", "http://native.request.test/"+test.path, nil)
		request.Header.Set("User-Agent", test.agent)
		if err = request.Write(client); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(reader, request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != test.status || string(body) != test.body {
			t.Fatalf("native HTTP rule %s: %d %q %v", test.path, response.StatusCode, body, err)
		}
	}
	client.Close()
	httpdebug.StopService()
	saved, err := httpdebug.Saved()
	if err != nil {
		t.Fatal(err)
	}
	items := saved.Page(20, "native.request.test").Items
	if len(items) != 5 {
		t.Fatalf("native requests missing: %+v", items)
	}
	for _, item := range items {
		if item.ConnectionID != connectionID || item.Outbound != "reject" || item.RequestRoute == nil {
			t.Fatalf("real native routing lost original connection metadata: %+v", item)
		}
		if item.Status == 200 && !strings.HasSuffix(item.URL, "/changed") {
			t.Fatalf("native selection used rewritten URL prematurely: %+v", item)
		}
	}
}

func TestBboxHTTPRequestsReselectNativeRulesAndKeepOwner(t *testing.T) {
	a := &requestTestOutbound{tag: "A", seen: make(chan adapter.InboundContext, 2)}
	b := &requestTestOutbound{tag: "B", seen: make(chan adapter.InboundContext, 2)}
	logger := log.NewNOPFactory().NewLogger("router")
	router := &Router{ctx: context.Background(), logger: logger, outbound: &requestTestOutboundManager{list: map[string]adapter.Outbound{"A": a, "B": b}}, dnsTransport: &requestTestDNSManager{}}
	for _, options := range []option.DefaultRule{
		{RawDefaultRule: option.RawDefaultRule{HTTPURLRegex: []string{`^http://origin\.test/url$`}}, RuleAction: option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: "A", RawRouteOptionsActionOptions: option.RawRouteOptionsActionOptions{OverridePort: 8081}}}},
		{RawDefaultRule: option.RawDefaultRule{HTTPUserAgent: []string{"AppB/*"}}, RuleAction: option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: "B"}}},
	} {
		rule, err := R.NewDefaultRule(context.Background(), logger, options)
		if err != nil {
			t.Fatal(err)
		}
		router.rules = append(router.rules, rule)
	}
	owner := &adapter.ConnectionOwner{UserId: 1234, PackageNames: []string{"com.original"}}
	original := adapter.InboundContext{Inbound: "tun", InboundType: C.TypeTun, Network: "tcp", Source: M.ParseSocksaddr("192.0.2.5:4321"), Destination: M.ParseSocksaddr("198.51.100.1:9999"), RouteOriginalDestination: M.ParseSocksaddr("198.51.100.1:80"), Domain: "origin.test", ProcessInfo: owner, RouteOutbound: "old", RouteRule: "old-rule", TLSFragment: true}
	selectRoute := router.debugRequestRouter(original, "http")
	keys := make(map[string]string)
	for _, test := range []struct {
		path, tag string
		port      uint16
	}{{"url", "A", 8081}, {"ua", "B", 80}} {
		request, _ := http.NewRequest("GET", "http://origin.test/"+test.path, nil)
		request.Header.Set("User-Agent", "AppB/1")
		plan, err := selectRoute(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if plan.Metadata.Outbound != test.tag {
			t.Fatalf("native rule order did not select %s: %+v", test.tag, plan.Metadata)
		}
		keys[test.tag] = plan.Key
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := plan.Dial(ctx, "")
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		request.Write(conn)
		response, err := http.ReadResponse(bufio.NewReader(conn), request)
		if err != nil {
			conn.Close()
			cancel()
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		conn.Close()
		cancel()
		if string(body) != test.tag {
			t.Fatalf("selected outbound did not forward request: %q", body)
		}
		outbound := a
		if test.tag == "B" {
			outbound = b
		}
		seen := <-outbound.seen
		if seen.Inbound != original.Inbound || seen.Source != original.Source || seen.ProcessInfo != owner || seen.Destination.Port != test.port || seen.TLSFragment || seen.RouteOutbound != test.tag || seen.HTTPURL != request.URL.String() {
			t.Fatalf("request route inherited stale route state or lost owner: %+v", seen)
		}
	}
	if keys["A"] == keys["B"] {
		t.Fatal("different request outbound/options shared a pool key")
	}
	if original.RouteOutbound != "old" || !original.TLSFragment || original.Destination.Port != 9999 {
		t.Fatal("request selection changed original connection metadata")
	}
}
