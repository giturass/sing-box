package httpdebug

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"sync"
)

// Pools belong to one intercepted client connection. A selected policy/member,
// native dial options and final origin all participate in the key, so HTTP/2 or
// HTTP/3 streams can reuse a connection only after making the same decision.
type requestTransportPool struct {
	ctx     context.Context
	route   RequestRouteFunc
	roots   *x509.CertPool
	mitm    *MITMConfig
	h3      bool
	mu      sync.Mutex
	closed  bool
	entries map[string]*requestTransportEntry
}

type requestTransportEntry struct {
	transport http.RoundTripper
	close     func()
}

func newRequestTransportPool(ctx context.Context, route RequestRouteFunc, roots *x509.CertPool, mitm *MITMConfig, h3 bool) *requestTransportPool {
	return &requestTransportPool{ctx: ctx, route: route, roots: roots, mitm: mitm, h3: h3, entries: make(map[string]*requestTransportEntry)}
}

func (p *requestTransportPool) roundTrip(request *http.Request, plan *RequestRoute, destination string) (*http.Response, error) {
	if plan == nil || plan.Key == "" {
		return nil, errors.New("HTTP request has no selected route")
	}
	h3 := p.h3 && destination == "" && plan.PacketDial != nil && request.URL.Scheme == "https"
	protocol := "tcp"
	if h3 {
		protocol = "udp"
	}
	key := plan.Key + "\x00" + protocol + "\x00" + request.URL.Scheme + "://" + request.URL.Host + "\x00" + destination
	p.mu.Lock()
	if p.closed || p.ctx.Err() != nil {
		p.mu.Unlock()
		return nil, net.ErrClosed
	}
	entry := p.entries[key]
	if entry == nil {
		var err error
		if h3 {
			entry, err = newHTTP3RequestTransport(p.ctx, plan, destination, request.URL.Hostname(), p.roots, p.mitm)
		} else {
			if plan.Dial == nil {
				err = errors.New("selected HTTP request policy does not support TCP")
			} else {
				entry = newTCPRequestTransport(p.ctx, plan.Dial, destination, request.URL.Hostname(), p.roots, p.mitm)
			}
		}
		if err != nil {
			p.mu.Unlock()
			return nil, err
		}
		p.entries[key] = entry
	}
	p.mu.Unlock()
	return entry.transport.RoundTrip(request)
}

func (p *requestTransportPool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	entries := p.entries
	p.entries = nil
	p.mu.Unlock()
	for _, entry := range entries {
		entry.close()
	}
}

// net/http can detach a pending dial from its opening request to reuse it.
// Own every routed socket and join every dial when the client/service exits.
type tcpRequestTransport struct {
	ctx         context.Context
	cancel      context.CancelFunc
	dial        RewriteDialFunc
	destination string
	transport   *http.Transport
	mu          sync.Mutex
	closed      bool
	connections map[*ownedRequestConn]struct{}
	wg          sync.WaitGroup
}

func newTCPRequestTransport(lifetime context.Context, dial RewriteDialFunc, destination, host string, roots *x509.CertPool, mitm *MITMConfig) *requestTransportEntry {
	ctx, cancel := context.WithCancel(lifetime)
	owned := &tcpRequestTransport{ctx: ctx, cancel: cancel, dial: dial, destination: destination, connections: make(map[*ownedRequestConn]struct{})}
	transport := newRewriteTransport(ctx, func(callCtx context.Context, _ string) (net.Conn, error) { return owned.open(callCtx) }, roots)
	transport.TLSClientConfig.ServerName = normalizeHost(host)
	if mitm != nil {
		transport.ForceAttemptHTTP2 = mitm.H2
		transport.TLSClientConfig.NextProtos = mitm.httpProtocols()
		transport.TLSClientConfig.InsecureSkipVerify = mitm.SkipServerCertVerify
	}
	owned.transport = transport
	return &requestTransportEntry{transport: transport, close: owned.Close}
}

func (t *tcpRequestTransport) open(callCtx context.Context) (net.Conn, error) {
	t.mu.Lock()
	if t.closed || t.ctx.Err() != nil {
		t.mu.Unlock()
		return nil, net.ErrClosed
	}
	t.wg.Add(1)
	t.mu.Unlock()
	defer t.wg.Done()
	ctx, cancel := context.WithCancel(callCtx)
	stop := context.AfterFunc(t.ctx, cancel)
	raw, err := t.dial(ctx, t.destination)
	if err == nil {
		err = ctx.Err()
	}
	if err != nil || raw == nil {
		stop()
		cancel()
		if raw != nil {
			_ = raw.Close()
		}
		if err == nil {
			err = errors.New("HTTP request route returned no connection")
		}
		return nil, err
	}
	owned := &ownedRequestConn{Conn: raw, owner: t, cancel: func() { stop(); cancel() }}
	t.mu.Lock()
	if t.closed || t.ctx.Err() != nil {
		t.mu.Unlock()
		_ = owned.Close()
		return nil, net.ErrClosed
	}
	t.connections[owned] = struct{}{}
	t.mu.Unlock()
	return owned, nil
}

func (t *tcpRequestTransport) Close() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	connections := make([]*ownedRequestConn, 0, len(t.connections))
	for conn := range t.connections {
		connections = append(connections, conn)
	}
	t.mu.Unlock()
	t.cancel()
	for _, conn := range connections {
		_ = conn.Close()
	}
	t.transport.CloseIdleConnections()
	t.wg.Wait()
}

type ownedRequestConn struct {
	net.Conn
	owner  *tcpRequestTransport
	cancel context.CancelFunc
	once   sync.Once
	err    error
}

func (c *ownedRequestConn) Close() error {
	c.once.Do(func() {
		c.cancel()
		c.err = c.Conn.Close()
		c.owner.mu.Lock()
		delete(c.owner.connections, c)
		c.owner.mu.Unlock()
	})
	return c.err
}
