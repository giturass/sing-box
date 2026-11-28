//go:build with_quic

package route

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/httpdebug"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type requestQUICOutbound struct {
	*captureQUICOutbound
	tag string
}

func (o *requestQUICOutbound) Tag() string     { return o.tag }
func (*requestQUICOutbound) Network() []string { return []string{N.NetworkUDP} }

func testBboxHTTPRequestQUICNativeRules(t *testing.T, directory string) {
	t.Helper()
	certificate, originRoots, pem, signer, clientRoots := captureQUICCertificates(t)
	outbounds := make(map[string]adapter.Outbound)
	counts := make(map[string]*atomic.Int32)
	for _, tag := range []string{"A", "B"} {
		raw, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		count := &atomic.Int32{}
		counts[tag] = count
		server := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{http3.NextProtoH3}},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				count.Add(1)
				_, _ = io.WriteString(w, tag)
			})}
		done := make(chan struct{})
		go func() { _ = server.Serve(raw); close(done) }()
		t.Cleanup(func() {
			_ = raw.Close()
			_ = server.Close()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("native request QUIC origin did not stop")
			}
		})
		outbounds[tag] = &requestQUICOutbound{tag: tag, captureQUICOutbound: &captureQUICOutbound{
			origin: raw.LocalAddr().(*net.UDPAddr), metadata: make(chan adapter.InboundContext, 4), closed: make(chan struct{}),
		}}
	}
	prepared, err := httpdebug.PrepareProcessing(directory,
		&httpdebug.MITMConfig{Enabled: true, H3: true, Hosts: []string{"origin.test"}, Ports: []uint16{443}, Packages: []string{"com.test"}},
		nil, nil, pem, signer, "UTC", httpdebug.ProcessingConfig{HTTPRouting: &httpdebug.HTTPRoutingConfig{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	httpdebug.ActivateProcessing(prepared, nil, originRoots)
	t.Cleanup(httpdebug.StopService)
	if err := httpdebug.Start(directory, `{"ports":[443]}`, "", nil); err != nil {
		t.Fatal(err)
	}
	logger := log.NewNOPFactory().NewLogger("native-request-quic")
	router := &Router{ctx: service.ContextWith[adapter.CertificateStore](context.Background(), &captureTestRoots{roots: originRoots}),
		logger: logger, outbound: &requestTestOutboundManager{list: outbounds}, dnsTransport: &requestTestDNSManager{}}
	for _, options := range []option.DefaultRule{
		{RawDefaultRule: option.RawDefaultRule{HTTPURLRegex: []string{`/native-url$`}}, RuleAction: option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: "A"}}},
		{RawDefaultRule: option.RawDefaultRule{HTTPUserAgent: []string{"AppB/*"}}, RuleAction: option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: "B"}}},
		{RuleAction: option.RuleAction{Action: C.RuleActionTypeReject, RejectOptions: option.RejectActionOptions{Method: C.RuleActionRejectMethodDefault, NoDrop: true}}},
	} {
		rule, err := R.NewDefaultRule(router.ctx, logger, options)
		if err != nil {
			t.Fatal(err)
		}
		router.rules = append(router.rules, rule)
	}
	manager := trafficcontrol.NewManager()
	t.Cleanup(manager.CloseAllConnections)
	router.trackers = []adapter.ConnectionTracker{manager}
	metadata := adapter.InboundContext{Network: N.NetworkUDP, Inbound: "tun", Domain: "origin.test",
		Source: M.ParseSocksaddr("192.0.2.2:4321"), Destination: M.ParseSocksaddr("198.51.100.9:443"),
		ProcessInfo: &adapter.ConnectionOwner{UserId: 12345, PackageNames: []string{"com.test"}}}
	// A known UDP application protocol must keep FINAL REJECT; only a genuine
	// H3 ClientHello may defer it and enter the HTTP request engine.
	opaqueClient, opaqueInbound := newDebugPacketPipe(metadata.Source, metadata.Destination)
	opaque := metadata
	opaque.Protocol = "stun"
	opaqueClosed := make(chan error, 1)
	router.RoutePacketConnectionEx(context.Background(), opaqueInbound, opaque, N.OnceClose(func(err error) { opaqueClosed <- err }))
	_ = opaqueClient.Close()
	if err := <-opaqueClosed; !R.IsRejected(err) {
		t.Fatal("pending HTTP rules bypassed non-HTTP UDP rejection", err)
	}
	clientPackets, inbound := newDebugPacketPipe(metadata.Source, metadata.Destination)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	t.Cleanup(cancel)
	go router.RoutePacketConnectionEx(ctx, inbound, metadata, nil)
	qt := &quic.Transport{Conn: clientPackets}
	t.Cleanup(func() { _ = clientPackets.Close(); _ = qt.Close() })
	conn, err := qt.Dial(ctx, metadata.Destination,
		&tls.Config{RootCAs: clientRoots, ServerName: "origin.test", MinVersion: tls.VersionTLS13, NextProtos: []string{http3.NextProtoH3}},
		&quic.Config{HandshakeIdleTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal("FINAL REJECT prevented native HTTP/3 request selection", err)
	}
	transport := &http3.Transport{}
	t.Cleanup(func() { _ = clientPackets.Close(); _ = transport.Close(); _ = conn.CloseWithError(0, "") })
	client := transport.NewClientConn(conn)
	for _, sample := range []struct {
		path, agent, body string
		status            int
	}{
		{"native-url", "AppB/1", "A", 200}, {"native-ua", "AppB/1", "B", 200},
		{"native-reject", "Other", "Request rejected by B-box routing\n", 403},
		{"native-ua", "AppB/2", "B", 200}, {"native-url", "Other", "A", 200},
	} {
		request, err := http.NewRequest("GET", "https://origin.test/"+sample.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("User-Agent", sample.agent)
		response, err := client.RoundTrip(request.WithContext(ctx))
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != sample.status || string(body) != sample.body || response.ProtoMajor != 3 {
			t.Fatalf("native QUIC %s: %d %q %v", sample.path, response.StatusCode, body, err)
		}
	}
	for tag, count := range counts {
		if count.Load() != 2 {
			t.Fatalf("native QUIC request crossed outbounds: %s=%d", tag, count.Load())
		}
	}
	connections := manager.Connections()
	if len(connections) != 1 || connections[0].Metadata.RouteOutbound != "reject" {
		t.Fatal("native QUIC initial rejection was replaced by a default policy", connections)
	}
	connectionID := connections[0].ID.String()
	_ = clientPackets.Close()
	_ = conn.CloseWithError(0, "")
	_ = qt.Close()
	httpdebug.StopService()
	saved, err := httpdebug.Saved()
	if err != nil {
		t.Fatal(err)
	}
	items := saved.Page(20, "/native-").Items
	if len(items) != 5 {
		t.Fatal("native QUIC request decisions were not recorded", items)
	}
	for _, item := range items {
		if item.ConnectionID != connectionID || item.Outbound != "reject" || item.RequestRoute == nil || item.RequestRoute.Network != N.NetworkUDP {
			t.Fatalf("native HTTP/3 connection and actual request route were conflated: %+v", item)
		}
	}
}
