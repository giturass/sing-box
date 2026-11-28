package httpdebug

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
)

// HTTPRoutingConfig controls the HTTP engine independently of recording and
// rewriting. Forced hosts only opt plaintext TCP into HTTP parsing; HTTPS still
// requires a matching MITM host and a trusted generated CA.
type HTTPRoutingConfig struct {
	Enabled              bool     `json:"enabled,omitempty"`
	ForceHTTPEngineHosts []string `json:"force_http_engine_hosts,omitempty"`
}

func (c *HTTPRoutingConfig) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errors.New("HTTP routing settings must be an object")
	}
	type plain HTTPRoutingConfig
	var value plain
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	*c = HTTPRoutingConfig(value)
	return c.validate()
}

func (c *HTTPRoutingConfig) validate() error {
	for _, pattern := range c.ForceHTTPEngineHosts {
		if _, err := parseForcedHTTPHost(pattern); err != nil {
			return err
		}
	}
	return nil
}

func (c *HTTPRoutingConfig) candidate(metadata Metadata) bool {
	if c == nil || !c.Enabled || metadata.Protocol != "" && metadata.Protocol != "http" {
		return false
	}
	// Port 80 is the normal plaintext HTTP engine. Force-host exclusions only
	// remove a match from the additional forced scope, not normal HTTP parsing.
	if metadata.Port == 80 {
		return true
	}
	for _, pattern := range c.ForceHTTPEngineHosts {
		rule, err := parseForcedHTTPHost(pattern)
		if err == nil && rule.matches(metadata) {
			return !rule.exclude
		}
	}
	return false
}

func parseForcedHTTPHost(pattern string) (mitmHost, error) {
	rule, err := parseMITMHost(pattern)
	if err != nil {
		return rule, fmt.Errorf("force HTTP engine host: %w", err)
	}
	if !rule.explicitPort {
		rule.port = 80
	}
	// Plain HTTP never has MITM's recovered-SNI exemption from a bare port.
	rule.explicitPort = true
	return rule, nil
}

type RequestRouteMetadata struct {
	Destination string `json:"destination"`
	Outbound    string `json:"outbound"`
	Rule        string `json:"rule"`
	Network     string `json:"network"`
}

// Selection sees the original request. Dialing separately accepts a rewritten
// destination; an empty address retains the route's selected destination and
// native route options. A route key includes the selected chain and options.
type RequestRoute struct {
	Key            string
	Metadata       RequestRouteMetadata
	Dial           RewriteDialFunc
	PacketDial     RequestPacketDialFunc
	RejectResponse string
}

type RequestRouteFunc func(context.Context, *http.Request) (*RequestRoute, error)
type RequestPacketDialFunc func(context.Context, string) (net.PacketConn, net.Addr, error)

func rewrittenRequestDestination(target *url.URL) string {
	port := target.Port()
	if port == "" {
		if target.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(target.Hostname(), port)
}

var ErrRequestRejected = errors.New("HTTP request rejected by routing rule")

func localRouteResponse(request *http.Request, action string) *http.Response {
	switch action {
	case "reject-200":
		return localRewriteResponse(request, http.StatusOK, http.Header{"Content-Type": {"text/plain; charset=utf-8"}}, nil)
	case "reject-dict":
		return localRewriteResponse(request, http.StatusOK, http.Header{"Content-Type": {"application/json"}}, []byte("{}"))
	case "reject-tinygif":
		const pixel = "GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00;"
		return localRewriteResponse(request, http.StatusOK, http.Header{"Content-Type": {"image/gif"}}, []byte(pixel))
	default:
		return localRewriteResponse(request, http.StatusForbidden, http.Header{"Content-Type": {"text/plain; charset=utf-8"}}, []byte("Request rejected by B-box routing\n"))
	}
}
