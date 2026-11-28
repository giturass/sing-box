package dns_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	boxCertificate "github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	boxOutbound "github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
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

// Keep a real DNS transport's Close in progress after its socket has closed.
// The whole box must await that cleanup before dismantling this outbound.
type bBoxDNSCloseOrderOutbound struct {
	bBoxIntegrationDNSOutbound
	connections      atomic.Int32
	closeStarted     chan struct{}
	closeStartedOnce sync.Once
	releaseClose     chan struct{}
	releaseCloseOnce sync.Once
	outboundClosed   chan struct{}
}

func (o *bBoxDNSCloseOrderOutbound) release() {
	o.releaseCloseOnce.Do(func() { close(o.releaseClose) })
}

func (o *bBoxDNSCloseOrderOutbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateStart {
		scope.Add(func() error {
			close(o.outboundClosed)
			if o.connections.Load() != 0 {
				return errors.New("default outbound closed before script DNS transports stopped")
			}
			return nil
		})
	}
	return nil
}

func (o *bBoxDNSCloseOrderOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := o.bBoxIntegrationDNSOutbound.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	o.connections.Add(1)
	return &bBoxDNSCloseOrderConn{Conn: conn, outbound: o}, nil
}

type bBoxDNSCloseOrderConn struct {
	net.Conn
	outbound *bBoxDNSCloseOrderOutbound
	once     sync.Once
	closeErr error
}

func (c *bBoxDNSCloseOrderConn) Close() error {
	c.once.Do(func() {
		c.closeErr = c.Conn.Close()
		c.outbound.closeStartedOnce.Do(func() { close(c.outbound.closeStarted) })
		<-c.outbound.releaseClose
		c.outbound.connections.Add(-1)
	})
	return c.closeErr
}

func bBoxDNSCloseOrderBox(t *testing.T, outbound *bBoxDNSCloseOrderOutbound) (*box.Box, adapter.DNSRouter, *bBoxIntegrationDNSFallback) {
	t.Helper()
	dnsRegistry := boxDNS.NewTransportRegistry()
	transport.RegisterUDP(dnsRegistry)
	fallback := new(bBoxIntegrationDNSFallback)
	boxDNS.RegisterTransport[struct{}](dnsRegistry, "test", func(context.Context, log.ContextLogger, string, struct{}) (adapter.DNSTransport, error) {
		return fallback, nil
	})
	outboundRegistry := boxOutbound.NewRegistry()
	var dnsRouter adapter.DNSRouter
	boxOutbound.Register[struct{}](outboundRegistry, "b-box-dns-close-test", func(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ struct{}) (adapter.Outbound, error) {
		if tag != outbound.Tag() {
			return nil, errors.New("box selected another default outbound")
		}
		dnsRouter = service.FromContext[adapter.DNSRouter](ctx)
		if dnsRouter == nil {
			return nil, errors.New("box did not install its DNS router before the outbound")
		}
		return outbound, nil
	})
	ctx := box.Context(context.Background(), inbound.NewRegistry(), outboundRegistry, endpoint.NewRegistry(), dnsRegistry, boxService.NewRegistry(), boxCertificate.NewRegistry())
	instance, err := box.New(box.Options{Context: ctx, Options: option.Options{
		Log:       &option.LogOptions{Disabled: true},
		DNS:       &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{Servers: []option.DNSServerOptions{{Type: "test", Tag: "fallback"}}, Final: "fallback"}},
		Route:     &option.RouteOptions{Final: outbound.Tag()},
		Outbounds: []option.Outbound{{Type: "b-box-dns-close-test", Tag: outbound.Tag()}},
	}})
	require.NoError(t, err)
	t.Cleanup(func() { outbound.release(); _ = instance.Close() })
	require.NoError(t, instance.Start())
	require.NotNil(t, dnsRouter)
	require.Same(t, outbound, instance.Outbound().Default())
	return instance, dnsRouter, fallback
}

func TestBBoxDNSScriptWholeBoxWaitsForDNSBeforeClosingDefaultOutbound(t *testing.T) {
	for _, mode := range []string{"udp-stall", "tcp-stall"} {
		t.Run(mode, func(t *testing.T) {
			address, requests := bBoxDNSWireServer(t, mode)
			outbound := &bBoxDNSCloseOrderOutbound{
				bBoxIntegrationDNSOutbound: bBoxIntegrationDNSOutbound{address: address},
				closeStarted:               make(chan struct{}), releaseClose: make(chan struct{}), outboundClosed: make(chan struct{}),
			}
			instance, dnsRouter, fallback := bBoxDNSCloseOrderBox(t, outbound)
			bBoxActivateDNSScript(t, t.TempDir(), "$done({server:'192.0.2.53'});")
			t.Cleanup(httpdebug.StopService)
			query := new(mDNS.Msg).SetQuestion("script.example.test.", mDNS.TypeA)
			completed := make(chan error, 1)
			dnsRouter.ExchangeAsync(context.Background(), query, adapter.DNSQueryOptions{Timeout: 5 * time.Second}, func(_ *mDNS.Msg, err error) { completed <- err })
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
					t.Fatal("the DNS query did not reach the real upstream")
				}
				break
			}
			closed := make(chan error, 1)
			go func() { closed <- instance.Close() }()
			select {
			case <-outbound.closeStarted:
			case <-time.After(time.Second):
				t.Fatal("Box.Close did not cancel its script DNS sockets")
			}
			select {
			case <-outbound.outboundClosed:
				t.Fatal("Box.Close dismantled the default outbound while DNS cleanup was pending")
			case err := <-closed:
				t.Fatalf("Box.Close returned before DNS cleanup completed: %v", err)
			case <-time.After(10 * time.Millisecond):
			}
			outbound.release()
			select {
			case err := <-closed:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("Box.Close did not finish after its DNS transports stopped")
			}
			select {
			case err := <-completed:
				require.ErrorIs(t, err, context.Canceled)
			case <-time.After(time.Second):
				t.Fatal("the cancelled whole-box DNS query did not finish")
			}
			select {
			case <-outbound.outboundClosed:
			default:
				t.Fatal("Box.Close did not dismantle the default outbound")
			}
			require.Zero(t, outbound.connections.Load())
			require.Zero(t, fallback.queries.Load())
			require.NoError(t, instance.Close())
		})
	}
}
