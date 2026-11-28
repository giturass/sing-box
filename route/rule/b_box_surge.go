package rule

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"
)

// ResolveRuleDestination shares one cancellable lookup across Surge IP and
// requires-resolve script conditions. Failed DNS is a routing error, rather
// than a false predicate which could silently select the next outbound.
func ResolveRuleDestination(router adapter.DNSRouter, metadata *adapter.InboundContext) bool {
	// A native DNS rule may reference a Surge text set. Query matching must
	// never look up its own question recursively; response matching consumes
	// the supplied DNS answer instead.
	if metadata.DNSFlow {
		return false
	}
	if metadata.Destination.IsIP() || len(metadata.DestinationAddresses) > 0 {
		return true
	}
	if metadata.RuleMatchError != nil || metadata.RuleMatchDNSResolved {
		return false
	}
	if metadata.SurgeNoResolve {
		return false
	}
	if metadata.PreMatch {
		metadata.RuleMatchNeedsResolution = true
		return false
	}
	metadata.RuleMatchDNSResolved = true
	if router == nil {
		metadata.RuleMatchError = fmt.Errorf("Surge rule resolution requires the active DNS router")
		return false
	}
	domain := metadata.Destination.Fqdn
	if domain == "" {
		domain = metadata.Domain
	}
	if domain == "" {
		return false
	}
	ctx := metadata.RuleMatchContext
	if ctx == nil {
		ctx = context.Background()
	}
	addresses, err := router.Lookup(adapter.WithContext(ctx, metadata), domain, adapter.DNSQueryOptions{})
	if err != nil {
		metadata.RuleMatchError = fmt.Errorf("resolve Surge rule destination %q: %w", domain, err)
		return false
	}
	if len(addresses) == 0 {
		metadata.RuleMatchError = fmt.Errorf("resolve Surge rule destination %q: no addresses", domain)
		return false
	}
	metadata.DestinationAddresses = addresses
	return true
}

type SurgeIPCIDRItem struct {
	inner     *IPCIDRItem
	router    adapter.DNSRouter
	noResolve bool
	ipv6      bool
}

func NewSurgeIPCIDRItem(ctx context.Context, prefixes []*badoption.Prefixable, noResolve bool) (*SurgeIPCIDRItem, error) {
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("missing Surge IP prefixes")
	}
	ipv6 := prefixes[0].Build(netip.Prefix{}).Addr().Is6()
	for _, prefix := range prefixes {
		if prefix.Build(netip.Prefix{}).Addr().Is6() != ipv6 {
			return nil, fmt.Errorf("a Surge IP rule must use one address family")
		}
	}
	inner, err := NewIPCIDRItem(false, prefixes)
	if err != nil {
		return nil, err
	}
	return &SurgeIPCIDRItem{inner: inner, router: service.FromContext[adapter.DNSRouter](ctx), noResolve: noResolve, ipv6: ipv6}, nil
}

func (r *SurgeIPCIDRItem) Match(metadata *adapter.InboundContext) bool {
	if metadata.IPCIDRMatchSource {
		return r.inner.ipSet.Contains(metadata.Source.Addr)
	}
	if metadata.DNSFlow || metadata.DestinationAddressMatchFromResponse {
		// DNS rules retain sing-box's any-address response filter and legacy
		// empty-answer option, even when their resource uses Surge syntax.
		return r.inner.Match(metadata)
	}
	if metadata.Destination.IsIP() {
		return r.inner.ipSet.Contains(metadata.Destination.Addr)
	}
	if len(metadata.DestinationAddresses) == 0 {
		if r.noResolve || metadata.SurgeNoResolve || !ResolveRuleDestination(r.router, metadata) {
			return false
		}
	}
	return r.matchFirst(metadata.DestinationAddresses)
}

func (r *SurgeIPCIDRItem) matchFirst(addresses []netip.Addr) bool {
	for _, address := range addresses {
		address = address.Unmap()
		if address.Is6() == r.ipv6 {
			return r.inner.ipSet.Contains(address)
		}
	}
	return false
}

func (r *SurgeIPCIDRItem) String() string {
	text := "surge_" + r.inner.String()
	if r.noResolve {
		text += " no-resolve"
	}
	return text
}

func httpRuleAuthorityHost(authority string) string {
	if authority == "" || strings.ContainsAny(authority, "\r\n\t /\\@?#") {
		return ""
	}
	if address, err := netip.ParseAddr(strings.Trim(authority, "[]")); err == nil {
		return address.String()
	}
	parsed, err := url.Parse("//" + authority)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
}

func HTTPRequestURLs(metadata *adapter.InboundContext) []string {
	if metadata.HTTPURL == "" {
		return nil
	}
	result := []string{metadata.HTTPURL}
	if !metadata.HTTPExtendedMatching {
		return result
	}
	parsed, err := url.Parse(metadata.HTTPURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return result
	}
	for _, authority := range []string{metadata.HTTPServerName, metadata.HTTPHost} {
		host := httpRuleAuthorityHost(authority)
		if host == "" {
			continue
		}
		candidate := *parsed
		if port := parsed.Port(); port != "" {
			candidate.Host = net.JoinHostPort(host, port)
		} else if strings.Contains(host, ":") {
			candidate.Host = "[" + host + "]"
		} else {
			candidate.Host = host
		}
		text := candidate.String()
		duplicate := false
		for _, existing := range result {
			if text == existing {
				duplicate = true
				break
			}
		}
		if !duplicate {
			result = append(result, text)
		}
	}
	return result
}

func httpRuleDomains(metadata *adapter.InboundContext) []string {
	domain := metadata.Domain
	if domain == "" {
		domain = metadata.Destination.Fqdn
	}
	result := []string{}
	if domain != "" {
		result = append(result, strings.ToLower(strings.TrimSuffix(domain, ".")))
	}
	if metadata.HTTPExtendedMatching && !metadata.DNSFlow {
		for _, authority := range []string{metadata.HTTPServerName, metadata.HTTPHost} {
			if host := httpRuleAuthorityHost(authority); host != "" {
				result = append(result, host)
			}
		}
	}
	return result
}

func markPendingHTTPDomain(metadata *adapter.InboundContext) {
	if metadata.HTTPExtendedMatching && !metadata.DNSFlow && metadata.HTTPURL == "" {
		metadata.RuleMatchPendingHTTP = true
	}
}
