package route

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/httpdebug"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func (r *Router) debugCanDeferReject(ctx context.Context, metadata adapter.InboundContext) bool {
	if ctx.Value(httpRewriteRouteKey{}) != nil || httpdebug.ProcessingDisabled(ctx) {
		return false
	}
	engine := httpdebug.Current()
	if metadata.Network == N.NetworkUDP {
		if engine == nil || !engine.H3Enabled() || metadata.Protocol != "" && metadata.Protocol != C.ProtocolQUIC {
			return false
		}
		info := debugMetadata(metadata)
		info.Protocol = "tls"
		return engine.RequestRoutingCandidate(info)
	}
	return engine != nil && engine.RequestRoutingCandidate(debugMetadata(metadata))
}

// Existing trackers need an outbound identity even while the terminal rule is
// a pending rejection. This view cannot forward bytes; the request callback is
// the only place that may choose a real outbound after HTTP parsing.
type debugRequestRejectOutbound struct{ action *R.RuleActionReject }

func (*debugRequestRejectOutbound) Tag() string            { return "reject" }
func (*debugRequestRejectOutbound) Type() string           { return C.RuleActionTypeReject }
func (*debugRequestRejectOutbound) Network() []string      { return []string{N.NetworkTCP, N.NetworkUDP} }
func (*debugRequestRejectOutbound) Dependencies() []string { return nil }
func (o *debugRequestRejectOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	if o.action.Method == C.RuleActionRejectMethodReply {
		return nil, errors.New("reject method `reply` is not supported for TCP connections")
	}
	return nil, o.action.Error(ctx)
}
func (o *debugRequestRejectOutbound) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	return nil, httpdebug.ErrRequestRejected
}

// Retain the connection's source/owner and the pre-override destination. Never
// carry selected outbound state, resolved addresses or match caches into another
// HTTP request. HTTP Host and TLS SNI are separate, opt-in matching candidates.
func debugRequestMetadata(connection adapter.InboundContext, protocol string) adapter.InboundContext {
	destination := connection.Destination
	if connection.RouteOriginalDestination.IsValid() {
		destination = connection.RouteOriginalDestination
	}
	if connection.Protocol != "" {
		protocol = connection.Protocol
	}
	return adapter.InboundContext{Inbound: connection.Inbound, InboundType: connection.InboundType,
		Source: connection.Source, Destination: destination, Network: connection.Network,
		User: connection.User, Protocol: protocol, Domain: connection.Domain,
		Client: connection.Client, ECHPublicName: connection.ECHPublicName,
		OriginDestination: connection.OriginDestination, FakeIP: connection.FakeIP,
		ProcessInfo: connection.ProcessInfo, SourceMACAddress: connection.SourceMACAddress,
		SourceHostname: connection.SourceHostname}
}

func (r *Router) debugRequestRouter(connection adapter.InboundContext, protocol string) httpdebug.RequestRouteFunc {
	base := debugRequestMetadata(connection, protocol)
	return func(ctx context.Context, request *http.Request) (*httpdebug.RequestRoute, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		metadata := base
		metadata.HTTPURL, metadata.HTTPUserAgent, metadata.HTTPHost = request.URL.String(), request.UserAgent(), request.Host
		if request.TLS != nil {
			metadata.HTTPServerName = request.TLS.ServerName
		}
		routeCtx := adapter.WithContext(context.WithValue(ctx, httpRewriteRouteKey{}, true), &metadata)
		matched, _, buffers, packets, err := r.matchRule(routeCtx, &metadata, nil, nil)
		if len(buffers) != 0 || len(packets) != 0 {
			buf.ReleaseMulti(buffers)
			N.ReleaseMultiPacketBuffer(packets)
			return nil, errors.New("HTTP request route unexpectedly read connection data")
		}
		if err != nil {
			return nil, err
		}
		plan := &httpdebug.RequestRoute{Metadata: httpdebug.RequestRouteMetadata{Destination: metadata.Destination.String(), Network: metadata.Network}}
		if matched != nil {
			metadata.RouteRule = matched.String()
			plan.Metadata.Rule = metadata.RouteRule
		}
		var policy adapter.Outbound
		if matched != nil {
			switch action := matched.Action().(type) {
			case *R.RuleActionRoute:
				var found bool
				policy, found = r.outbound.Outbound(action.Outbound)
				if !found {
					return plan, fmt.Errorf("HTTP request outbound not found: %s", action.Outbound)
				}
			case *R.RuleActionBypass:
				if action.Outbound != "" {
					var found bool
					policy, found = r.outbound.Outbound(action.Outbound)
					if !found {
						return plan, fmt.Errorf("HTTP request outbound not found: %s", action.Outbound)
					}
				}
			case *R.RuleActionReject:
				plan.Metadata.Outbound = "reject"
				plan.RejectResponse = action.HTTPResponse
				if plan.RejectResponse != "" {
					return plan, nil
				}
				rejected := action.Error(ctx)
				if errors.Is(rejected, R.ErrDrop) {
					return plan, errors.Join(httpdebug.ErrRequestRejected, rejected)
				}
				plan.RejectResponse = "reject"
				return plan, nil
			case *R.RuleActionHijackDNS:
				return plan, errors.New("DNS hijacking cannot forward an HTTP request")
			}
		}
		if policy == nil {
			policy = r.outbound.Default()
		}
		if policy == nil {
			return plan, errors.New("HTTP request route has no outbound")
		}
		metadata.RouteOutbound, plan.Metadata.Outbound = policy.Tag(), policy.Tag()
		var tcpChain, udpChain []adapter.Outbound
		tcpChain, tcpErr := resolveOutbound(policy, N.NetworkTCP)
		var udpErr error
		if metadata.Network == N.NetworkUDP {
			udpChain, udpErr = resolveOutbound(policy, N.NetworkUDP)
		}
		if metadata.Network == N.NetworkTCP && tcpErr != nil {
			return plan, tcpErr
		}
		if metadata.Network == N.NetworkUDP && udpErr != nil && tcpErr != nil {
			return plan, udpErr
		}
		plan.Key = debugRequestRouteKey(metadata, tcpChain, udpChain)
		if tcpErr == nil {
			plan.Dial = func(callCtx context.Context, address string) (net.Conn, error) {
				if err := callCtx.Err(); err != nil {
					return nil, err
				}
				dialMetadata, err := debugRequestDialMetadata(metadata, address, N.NetworkTCP, tcpChain)
				if err != nil {
					return nil, err
				}
				local, routed := net.Pipe()
				done := make(chan struct{})
				stop := context.AfterFunc(callCtx, func() { _ = local.Close(); _ = routed.Close() })
				closed := N.OnceClose(func(error) { stop(); _ = routed.Close(); close(done) })
				closed = registerInterrupt(tcpChain, routed, closed)
				dialCtx := adapter.WithContext(interrupt.ContextWithIsExternalConnection(context.WithValue(callCtx, httpRewriteRouteKey{}, true), true), &dialMetadata)
				go func() {
					outbound := tcpChain[len(tcpChain)-1]
					if handler, ok := outbound.(adapter.ConnectionHandler); ok {
						handler.NewConnection(dialCtx, routed, dialMetadata, closed)
					} else {
						r.connection.NewConnection(dialCtx, outbound, routed, dialMetadata, closed)
					}
				}()
				return &debugRoutedRequestConn{Conn: local, done: done}, nil
			}
		}
		if len(udpChain) > 0 {
			plan.PacketDial = func(callCtx context.Context, address string) (net.PacketConn, net.Addr, error) {
				if err := callCtx.Err(); err != nil {
					return nil, nil, err
				}
				dialMetadata, err := debugRequestDialMetadata(metadata, address, N.NetworkUDP, udpChain)
				if err != nil {
					return nil, nil, err
				}
				local, routed := newDebugPacketPipe(dialMetadata.Source, dialMetadata.Destination)
				done := make(chan struct{})
				closed := N.OnceClose(func(error) { _ = routed.Close(); close(done) })
				closed = registerInterrupt(udpChain, routed, closed)
				dialCtx := adapter.WithContext(interrupt.ContextWithIsExternalConnection(context.WithValue(callCtx, httpRewriteRouteKey{}, true), true), &dialMetadata)
				go func() {
					outbound := udpChain[len(udpChain)-1]
					if handler, ok := outbound.(adapter.PacketConnectionHandler); ok {
						handler.NewPacketConnection(dialCtx, routed, dialMetadata, closed)
					} else {
						r.connection.NewPacketConnection(dialCtx, outbound, routed, dialMetadata, closed)
					}
				}()
				owned := &debugRoutedPacketConn{PacketConn: local, done: done}
				return &debugFixedPacketPeer{PacketConn: owned, peer: dialMetadata.Destination}, dialMetadata.Destination, nil
			}
		}
		return plan, nil
	}
}

func debugRequestDialMetadata(selection adapter.InboundContext, address, network string, chain []adapter.Outbound) (adapter.InboundContext, error) {
	metadata := selection
	metadata.Network, metadata.OutboundChain = network, chain
	metadata.RuleMatchContext, metadata.RuleScriptResults, metadata.RuleMatchError = nil, nil, nil
	if address != "" {
		destination := M.ParseSocksaddr(address)
		if !destination.IsValid() || destination.Port == 0 {
			return metadata, errors.New("invalid routed HTTP destination")
		}
		metadata.Destination, metadata.Domain = destination, destination.Fqdn
		metadata.DestinationAddresses, metadata.DNSResponse, metadata.NamedDNSResponses = nil, nil, nil
		metadata.OriginDestination, metadata.RouteOriginalDestination = M.Socksaddr{}, M.Socksaddr{}
		metadata.FakeIP, metadata.DestinationAddressMatchFromResponse = false, false
	}
	return metadata, nil
}

// A group's selected member, DNS result, destination or native dial option may
// change between requests. None may reuse a transport created for another plan.
func debugRequestRouteKey(metadata adapter.InboundContext, tcp, udp []adapter.Outbound) string {
	tags := func(chain []adapter.Outbound) []string {
		values := make([]string, 0, len(chain))
		for _, outbound := range chain {
			values = append(values, outbound.Tag())
		}
		return values
	}
	value := struct {
		TCP, UDP                                                              []string
		Destination, Rule                                                     string
		Addresses                                                             []netip.Addr
		UDPConnect, UDPDisableDomainUnmapping, TLSFragment, TLSRecordFragment bool
		UDPTimeout, TLSFragmentFallbackDelay, FallbackDelay                   time.Duration
		TLSSpoof                                                              string
		TLSSpoofMethod                                                        any
		NetworkStrategy                                                       any
		NetworkType, FallbackNetworkType                                      any
	}{tags(tcp), tags(udp), metadata.Destination.String(), metadata.RouteRule, metadata.DestinationAddresses,
		metadata.UDPConnect, metadata.UDPDisableDomainUnmapping, metadata.TLSFragment, metadata.TLSRecordFragment,
		metadata.UDPTimeout, metadata.TLSFragmentFallbackDelay, metadata.FallbackDelay,
		metadata.TLSSpoof, metadata.TLSSpoofMethod, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType}
	data, _ := json.Marshal(value)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

type debugRoutedRequestConn struct {
	net.Conn
	done <-chan struct{}
	once sync.Once
}

func (c *debugRoutedRequestConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { <-c.done })
	return err
}
