package rule

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

// Surge protocol values are case-sensitive. TCP/UDP are network umbrellas;
// HTTP/HTTPS retain the original URL scheme after MITM. Opaque TLS is not
// evidence of HTTPS, and Surge's own DNS/DO* traffic has no B-box equivalent.
type SurgeProtocolItem struct {
	values       []string
	waitsForHTTP bool
}

func NewSurgeProtocolItem(values []string) (*SurgeProtocolItem, error) {
	item := &SurgeProtocolItem{values: values}
	for _, value := range values {
		switch value {
		case "HTTP", "HTTPS":
			item.waitsForHTTP = true
		case "TCP", "UDP", "QUIC", "STUN":
		default:
			return nil, fmt.Errorf("unsupported or invalid Surge protocol %q", value)
		}
	}
	return item, nil
}

func (r *SurgeProtocolItem) Match(metadata *adapter.InboundContext) bool {
	if metadata.PreMatch {
		metadata.RuleMatchNeedsResolution = true
		return false
	}
	protocol := observedSurgeProtocol(metadata)
	for _, value := range r.values {
		if value == protocol || value == "TCP" && metadata.Network == "tcp" || value == "UDP" && metadata.Network == "udp" || value == "QUIC" && metadata.Protocol == C.ProtocolQUIC || value == "STUN" && metadata.Protocol == C.ProtocolSTUN {
			return true
		}
	}
	if r.waitsForHTTP && (metadata.DNSFlow || metadata.HTTPURL == "" && metadata.Protocol != C.ProtocolHTTP) {
		metadata.RuleMatchPendingHTTP = true
	}
	return false
}

func observedSurgeProtocol(metadata *adapter.InboundContext) string {
	if metadata.DNSFlow {
		// A DNS question has no HTTP request. Native DNS source protocol
		// conditions may still use the connection's sniffed protocol.
		switch metadata.Protocol {
		case C.ProtocolQUIC:
			return "QUIC"
		case C.ProtocolSTUN:
			return "STUN"
		default:
			return ""
		}
	}
	if metadata.HTTPURL != "" {
		parsed, err := url.Parse(metadata.HTTPURL)
		if err == nil {
			switch parsed.Scheme {
			case "http":
				return "HTTP"
			case "https":
				return "HTTPS"
			}
		}
		return ""
	}
	switch metadata.Protocol {
	case C.ProtocolHTTP:
		return "HTTP"
	case C.ProtocolQUIC:
		return "QUIC"
	case C.ProtocolSTUN:
		return "STUN"
	default:
		return ""
	}
}

func (r *SurgeProtocolItem) String() string { return "surge_protocol=" + strings.Join(r.values, "|") }
