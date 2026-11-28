package dns

import (
	"context"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

// A script-selected DNS server follows the existing default outbound. This
// transport-local view does not register an outbound or change the manager.
type bBoxDNSOutboundManager struct {
	adapter.OutboundManager
	defaultOutbound adapter.Outbound
	lifetime        context.Context
}

func (m *bBoxDNSOutboundManager) Default() adapter.Outbound {
	return &bBoxDefaultDNSOutbound{Outbound: m.defaultOutbound, lifetime: m.lifetime}
}

func (m *bBoxDNSOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.OutboundManager.Outbound(tag)
	if loaded && tag == m.defaultOutbound.Tag() {
		return &bBoxDefaultDNSOutbound{Outbound: outbound, lifetime: m.lifetime}, true
	}
	return outbound, loaded
}

type bBoxDefaultDNSOutbound struct {
	adapter.Outbound
	lifetime context.Context
}

// The adapter intentionally does not expose IsEmpty. Selecting the current
// default direct outbound is meaningful even though an arbitrary detour to an
// empty direct outbound is normally rejected by the generic DNS dialer.
func (o *bBoxDefaultDNSOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := o.Outbound.DialContext(ctx, network, destination)
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = o.lifetime.Err()
	}
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, err
	}
	wrapped := &bBoxDNSCancelConn{Conn: conn}
	// The native connection pool cancels its temporary dial context as soon as
	// the connection is installed. Bind the connection to the DNS call instead;
	// TCP exchange deadlines are handled by NeedAdditionalReadDeadline below.
	wrapped.stop = context.AfterFunc(o.lifetime, func() { _ = wrapped.closeTransport() })
	return wrapped, nil
}

type bBoxDNSCancelConn struct {
	net.Conn
	once     sync.Once
	stop     func() bool
	closeErr error
}

func (c *bBoxDNSCancelConn) closeTransport() error {
	c.once.Do(func() { c.closeErr = c.Conn.Close() })
	return c.closeErr
}

func (c *bBoxDNSCancelConn) Close() error {
	c.stop()
	return c.closeTransport()
}

func (c *bBoxDNSCancelConn) NeedAdditionalReadDeadline() bool { return true }
func (c *bBoxDNSCancelConn) Upstream() any                    { return c.Conn }
