package rule

import (
	"fmt"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestScriptRuleDNSFlowDoesNotExecuteResolveOrReuseCachedHTTPResults(t *testing.T) {
	for _, requiresResolve := range []bool{false, true} {
		t.Run(fmt.Sprintf("requires-resolve=%t", requiresResolve), func(t *testing.T) {
			ctx, dns := startRuleScriptTest(t, `
var n=Number($persistentStore.read('dns-scope-runs')||0)+1;
$persistentStore.write(String(n),'dns-scope-runs'); $done({matched:n===1});`)
			item, err := NewScriptItem(ctx, "choose", requiresResolve)
			require.NoError(t, err)
			metadata := ruleScriptMetadata(ctx)
			metadata.DNSFlow = true
			metadata.RuleScriptResults = map[string]bool{"choose": true}
			require.False(t, item.Match(&metadata), "DNS used a cached route SCRIPT result")
			require.True(t, metadata.RuleMatchPendingHTTP, "an unavailable SCRIPT condition must remain unknown")
			require.Zero(t, dns.calls, "SCRIPT requires-resolve recursively looked up a DNS question")
			require.NoError(t, metadata.RuleMatchError)
			require.False(t, metadata.RuleMatchDNSResolved)
			require.Empty(t, metadata.DestinationAddresses)
			require.Equal(t, map[string]bool{"choose": true}, metadata.RuleScriptResults)
			// Leaving DNS scope must preserve normal routing and prove JavaScript
			// was not executed invisibly while the DNS predicate was unavailable.
			request := ruleScriptMetadata(ctx)
			require.True(t, item.Match(&request), "normal routing was not the script's first invocation")
			request = ruleScriptMetadata(ctx)
			require.False(t, item.Match(&request), "a new route request reused the first script result")
			expectedLookups := 0
			if requiresResolve {
				expectedLookups = 2
			}
			require.Equal(t, expectedLookups, dns.calls)
		})
	}
}

func TestScriptDNSRuleSharedSetsKeepUnknownThroughNOTAndRestoreHTTPObservations(t *testing.T) {
	ctx, dns := startRuleScriptTest(t, `
var n=Number($persistentStore.read('shared-dns-scope-runs')||0)+1;
$persistentStore.write(String(n),'shared-dns-scope-runs'); $done({matched:n===1});`)
	router := &ruleSetItemTestRouter{ruleSets: make(map[string]adapter.RuleSet)}
	ctx = service.ContextWith[adapter.Router](ctx, router)
	for tag, text := range map[string]string{
		"script":     "SCRIPT,choose",
		"resolved":   "SCRIPT,choose,requires-resolve",
		"not-script": "NOT,((SCRIPT,choose))",
		"mixed":      "OR,((SCRIPT,choose,requires-resolve),(DOMAIN,api.test))",
	} {
		plain, warnings, err := option.ParseSurgeRuleSet([]byte(text), C.RuleSetFormatSurgeRules)
		require.NoError(t, err)
		require.Empty(t, warnings)
		set, err := NewLocalRuleSet(ctx, log.NewNOPFactory().Logger(), tag, option.RuleSet{Type: C.RuleSetTypeInline, InlineOptions: plain})
		require.NoError(t, err)
		router.ruleSets[tag] = set
		t.Cleanup(func() { require.NoError(t, set.Close()) })
	}
	for _, test := range []struct {
		name, content string
		want          bool
	}{
		{"plain SCRIPT", `{"rule_set":"script","server":"dns"}`, false},
		{"requires-resolve SCRIPT", `{"rule_set":"resolved","server":"dns"}`, false},
		{"Surge NOT SCRIPT", `{"rule_set":"not-script","server":"dns"}`, false},
		{"native invert SCRIPT", `{"rule_set":"script","invert":true,"server":"dns"}`, false},
		{"native logical NOT SCRIPT", `{"type":"logical","mode":"and","invert":true,"rules":[{"rule_set":"script"}],"server":"dns"}`, false},
		{"mixed text known domain", `{"rule_set":"mixed","server":"dns"}`, true},
		{"mixed native known domain", `{"type":"logical","mode":"or","rules":[{"rule_set":"resolved"},{"domain":"api.test"}],"server":"dns"}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, legacy := range []bool{false, true} {
				var options option.DNSRule
				require.NoError(t, json.UnmarshalContext(ctx, []byte(test.content), &options))
				dnsRule, err := NewDNSRule(ctx, log.NewNOPFactory().Logger(), options, true, legacy)
				require.NoError(t, err)
				require.NoError(t, dnsRule.Start())
				t.Cleanup(func() { require.NoError(t, dnsRule.Close()) })
				for _, api := range []string{"Match", "LegacyPreMatch", "MatchAddressLimit"} {
					metadata := ruleScriptMetadata(ctx)
					metadata.Domain = "api.test"
					metadata.HTTPHost = "inherited-host.test"
					metadata.HTTPServerName = "inherited-sni.test"
					metadata.RuleScriptResults = map[string]bool{"choose": true}
					original := metadata
					var matched bool
					switch api {
					case "Match":
						matched = dnsRule.Match(&metadata)
					case "LegacyPreMatch":
						matched = dnsRule.LegacyPreMatch(&metadata)
					case "MatchAddressLimit":
						matched = dnsRule.MatchAddressLimit(&metadata, new(mDNS.Msg))
					}
					require.Equal(t, test.want, matched, "%s legacy=%t inverted unknown or lost a known domain winner", api, legacy)
					if api != "MatchAddressLimit" {
						require.Equal(t, !test.want, metadata.RuleMatchPendingHTTP)
					}
					require.False(t, metadata.DNSFlow, "%s leaked DNS scope to its caller", api)
					require.Equal(t, original.HTTPURL, metadata.HTTPURL)
					require.Equal(t, original.HTTPUserAgent, metadata.HTTPUserAgent)
					require.Equal(t, original.HTTPHost, metadata.HTTPHost)
					require.Equal(t, original.HTTPServerName, metadata.HTTPServerName)
					require.Zero(t, dns.calls)
					require.NoError(t, metadata.RuleMatchError)
				}
			}
		})
	}
	item, err := NewScriptItem(ctx, "choose", false)
	require.NoError(t, err)
	request := ruleScriptMetadata(ctx)
	require.True(t, item.Match(&request), "shared DNS rules executed the route script before the first route request")
	require.Zero(t, dns.calls)
}
