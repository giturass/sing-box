package rule

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestHTTPRequestMatchersSurgePatternsAndCancellation(t *testing.T) {
	urlRule, err := NewHTTPURLRegexItem([]string{`(?<=/path/)secret(?=\?)`})
	if err != nil {
		t.Fatal(err)
	}
	userAgent, err := NewHTTPUserAgentItem([]string{"App?/*", "literal.[x]"})
	if err != nil {
		t.Fatal(err)
	}
	metadata := adapter.InboundContext{HTTPURL: "https://example.test/path/secret?q=1", HTTPUserAgent: "App1/1.0", RuleMatchContext: context.Background()}
	if !urlRule.Match(&metadata) || !userAgent.Match(&metadata) {
		t.Fatal("Surge lookaround or wildcard matching failed")
	}
	metadata.HTTPURL, metadata.HTTPUserAgent = "https://example.test/path/Secret?q=1", "app1/1.0"
	if urlRule.Match(&metadata) || userAgent.Match(&metadata) {
		t.Fatal("request matchers ignored case")
	}
	metadata.HTTPUserAgent = "literal.[x]"
	if !userAgent.Match(&metadata) {
		t.Fatal("User-Agent wildcard interpreted regexp punctuation")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	metadata.RuleMatchContext = ctx
	if urlRule.Match(&metadata) || metadata.RuleMatchError != context.Canceled {
		t.Fatal("cancelled request matching continued to another rule")
	}
}

func TestHTTPRequestConditionMissingDoesNotMatchNOT(t *testing.T) {
	negated, err := NewDefaultHeadlessRule(context.Background(), option.DefaultHeadlessRule{HTTPUserAgent: []string{"App*"}, Invert: true})
	if err != nil {
		t.Fatal(err)
	}
	metadata := adapter.InboundContext{}
	if negated.Match(&metadata) || !metadata.RuleMatchPendingHTTP {
		t.Fatal("NOT User-Agent matched an unparsed connection")
	}
	logical, err := NewLogicalHeadlessRule(context.Background(), option.LogicalHeadlessRule{Mode: C.LogicalTypeOr, Rules: []option.HeadlessRule{
		{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{HTTPUserAgent: []string{"App*"}}},
		{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{Domain: []string{"example.test"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	metadata = adapter.InboundContext{Domain: "example.test"}
	if !logical.Match(&metadata) || metadata.RuleMatchPendingHTTP {
		t.Fatal("a known OR branch was lost behind an unparsed HTTP condition")
	}
	metadata = adapter.InboundContext{HTTPURL: "http://example.test/", HTTPUserAgent: "Other"}
	if !negated.Match(&metadata) {
		t.Fatal("parsed negative User-Agent failed")
	}
}

func TestHTTPRequestHeadlessDNSFlowIgnoresInheritedURLAndUserAgent(t *testing.T) {
	for _, sample := range []struct {
		name    string
		options option.DefaultHeadlessRule
		matched bool
	}{
		{"URL-match", option.DefaultHeadlessRule{HTTPURLRegex: []string{`/secret$`}}, true},
		{"URL-miss", option.DefaultHeadlessRule{HTTPURLRegex: []string{`/other$`}}, false},
		{"UA-match", option.DefaultHeadlessRule{HTTPUserAgent: []string{"App*"}}, true},
		{"UA-miss", option.DefaultHeadlessRule{HTTPUserAgent: []string{"Other*"}}, false},
	} {
		for _, invert := range []bool{false, true} {
			name := sample.name
			if invert {
				name += "/NOT"
			}
			t.Run(name, func(t *testing.T) {
				options := sample.options
				options.Invert = invert
				rule, err := NewDefaultHeadlessRule(context.Background(), options)
				if err != nil {
					t.Fatal(err)
				}
				metadata := adapter.InboundContext{DNSFlow: true, Domain: "lookup.test", Network: "udp", Protocol: "quic",
					HTTPURL: "https://origin.test/secret", HTTPUserAgent: "App1/1.0", HTTPHost: "origin.test", HTTPServerName: "sni.test",
					RuleMatchContext: context.Background()}
				original := metadata
				if rule.Match(&metadata) || !metadata.RuleMatchPendingHTTP {
					t.Fatal("headless DNS flow matched or negated an inherited HTTP condition")
				}
				if !metadata.DNSFlow || metadata.Domain != original.Domain || metadata.Network != original.Network || metadata.Protocol != original.Protocol ||
					metadata.HTTPURL != original.HTTPURL || metadata.HTTPUserAgent != original.HTTPUserAgent || metadata.HTTPHost != original.HTTPHost || metadata.HTTPServerName != original.HTTPServerName {
					t.Fatal("DNS flow HTTP guard altered inherited connection fields")
				}
				metadata.DNSFlow = false
				metadata.ResetRuleCache()
				if matched := rule.Match(&metadata); matched != (sample.matched != invert) || metadata.RuleMatchPendingHTTP {
					t.Fatal("DNS flow guard changed ordinary parsed HTTP matching")
				}
			})
		}
	}
}
