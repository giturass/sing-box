//go:build !with_quic

package httpdebug

import (
	"context"
	"crypto/x509"
	"errors"
)

func newHTTP3RequestTransport(context.Context, *RequestRoute, string, string, *x509.CertPool, *MITMConfig) (*requestTransportEntry, error) {
	return nil, errors.New("HTTP/3 request routing requires the QUIC build")
}
