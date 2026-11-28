package dns

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
)

// A DNS lookup inherits source ownership, but its rule evaluation must never
// inherit an HTTP request, a route script result or that route's resolved IPs.
// Keep this request's context even when legacy Lookup has no QueryType.
func prepareBBoxDNSRuleMetadata(ctx context.Context, metadata *adapter.InboundContext) {
	metadata.DNSFlow = true
	metadata.RuleMatchContext = ctx
	metadata.RuleMatchError = nil
	metadata.RuleScriptResults = nil
	metadata.RuleMatchDNSResolved = false
	metadata.RuleMatchNeedsResolution = false
	metadata.RuleMatchNeedsHTTP = false
	metadata.RuleMatchPendingHTTP = false
	metadata.DestinationAddresses = nil
	metadata.HTTPURL, metadata.HTTPUserAgent, metadata.HTTPHost, metadata.HTTPServerName = "", "", "", ""
	metadata.HTTPExtendedMatching, metadata.SurgeNoResolve = false, false
}
