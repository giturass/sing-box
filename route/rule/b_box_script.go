package rule

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/httpdebug"
	"github.com/sagernet/sing/service"
)

// A SCRIPT rule is a condition. Its containing rule chooses the outbound;
// JavaScript cannot supply an unvalidated policy or cache it across requests.
type ScriptItem struct {
	name            string
	requiresResolve bool
	dns             adapter.DNSRouter
}

func NewScriptItem(ctx context.Context, name string, requiresResolve bool) (*ScriptItem, error) {
	if declarations := service.FromContext[*httpdebug.ScriptDeclarations](ctx); declarations != nil && !declarations.Rule[name] {
		return nil, fmt.Errorf("rule script %q is not configured", name)
	}
	return &ScriptItem{name: name, requiresResolve: requiresResolve, dns: service.FromContext[adapter.DNSRouter](ctx)}, nil
}

func (r *ScriptItem) Match(metadata *adapter.InboundContext) bool {
	if metadata.DNSFlow {
		metadata.RuleMatchPendingHTTP = true
		return false
	}
	if metadata.HTTPURL == "" {
		metadata.RuleMatchNeedsHTTP = true
	}
	if metadata.PreMatch {
		metadata.RuleMatchNeedsResolution = true
		return false
	}
	ctx := metadata.RuleMatchContext
	if ctx == nil {
		ctx = context.Background()
	}
	if httpdebug.ScriptEvaluationDisabled(ctx) {
		return false
	}
	if r.requiresResolve && !ResolveRuleDestination(r.dns, metadata) {
		return false
	}
	// Each reference applies its resolution requirement, while the script's
	// first result remains cached by name for this request's whole evaluation.
	if matched, found := metadata.RuleScriptResults[r.name]; found {
		return matched
	}
	request := httpdebug.RuleScriptRequest{
		Hostname: metadata.Domain, DestPort: metadata.Destination.Port, SourcePort: metadata.Source.Port,
		UserAgent: metadata.HTTPUserAgent, URL: metadata.HTTPURL,
		Resolved:  r.requiresResolve && (metadata.RuleMatchDNSResolved || len(metadata.DestinationAddresses) > 0),
		DNSResult: append([]netip.Addr(nil), metadata.DestinationAddresses...),
	}
	if request.Hostname == "" {
		request.Hostname = metadata.Destination.AddrString()
	}
	if metadata.Source.Addr.IsValid() {
		request.SourceIP = metadata.Source.Addr.Unmap().String()
	}
	if metadata.ProcessInfo != nil && len(metadata.ProcessInfo.ProcessPaths) > 0 {
		request.ProcessPath = metadata.ProcessInfo.ProcessPaths[0]
	}
	switch {
	case strings.HasPrefix(metadata.HTTPURL, "https:"):
		request.Protocol = "HTTPS"
	case metadata.HTTPURL != "" || metadata.Protocol == "http":
		request.Protocol = "HTTP"
	case metadata.Protocol == "quic":
		request.Protocol = "QUIC"
	case metadata.Protocol == "stun":
		request.Protocol = "STUN"
	case metadata.Network == "udp":
		request.Protocol = "UDP"
	default:
		request.Protocol = "TCP"
	}
	matched, err := httpdebug.MatchRuleScript(ctx, r.name, request)
	if err != nil {
		matched = false
		if ctx.Err() != nil {
			metadata.RuleMatchError = ctx.Err()
		} else if errors.Is(err, context.Canceled) {
			metadata.RuleMatchError = err
		}
	}
	if metadata.RuleScriptResults == nil {
		metadata.RuleScriptResults = make(map[string]bool)
	}
	metadata.RuleScriptResults[r.name] = matched
	return matched
}

func (r *ScriptItem) String() string { return "script=" + r.name }
