//go:build with_quic

package httpdebug

import (
	"context"
	"crypto/x509"
	"net"
)

func newHTTP3RequestTransport(ctx context.Context, plan *RequestRoute, destination, host string, roots *x509.CertPool, mitm *MITMConfig) (*requestTransportEntry, error) {
	skipVerify := mitm != nil && mitm.SkipServerCertVerify
	upstream := newHTTP3Upstream(ctx, func(callCtx context.Context) (net.PacketConn, net.Addr, error) {
		return plan.PacketDial(callCtx, destination)
	}, host, roots, skipVerify)
	return &requestTransportEntry{transport: upstream, close: upstream.Close}, nil
}
