package rule

import (
	"context"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func bboxSurgeDNSRule(t *testing.T, ctx context.Context, config string, legacy bool) adapter.DNSRule {
	t.Helper()
	var options option.DNSRule
	require.NoError(t, json.UnmarshalContext(ctx, []byte(config), &options))
	rule, err := NewDNSRule(ctx, log.NewNOPFactory().NewLogger("test"), options, true, legacy)
	require.NoError(t, err)
	require.NoError(t, rule.Start())
	t.Cleanup(func() { require.NoError(t, rule.Close()) })
	return rule
}

func bboxSurgeDNSResponse(addresses ...string) *mDNS.Msg {
	response := &mDNS.Msg{MsgHdr: mDNS.MsgHdr{Response: true, Rcode: mDNS.RcodeSuccess}}
	for _, text := range addresses {
		address := netip.MustParseAddr(text).Unmap()
		header := mDNS.RR_Header{Name: "lookup.test.", Class: mDNS.ClassINET, Ttl: 60}
		if address.Is4() {
			header.Rrtype = mDNS.TypeA
			response.Answer = append(response.Answer, &mDNS.A{Hdr: header, A: address.AsSlice()})
		} else {
			header.Rrtype = mDNS.TypeAAAA
			response.Answer = append(response.Answer, &mDNS.AAAA{Hdr: header, AAAA: address.AsSlice()})
		}
	}
	return response
}

func TestBboxSurgeDNSFlowDoesNotResolveItsQuestionAndKeepsNativeResponseFilters(t *testing.T) {
	t.Parallel()
	var lookups atomic.Int32
	dnsRouter := &bboxSurgeDNS{lookup: func(context.Context, string) ([]netip.Addr, error) {
		lookups.Add(1)
		return nil, fmt.Errorf("DNS rule recursively resolved its own question")
	}}
	router := &addressFilterRouter{ruleSets: make(map[string]adapter.RuleSet)}
	ctx := service.ContextWith[adapter.DNSRouter](context.Background(), dnsRouter)
	ctx = service.ContextWith[adapter.Router](ctx, router)
	for tag, text := range map[string]string{
		"v4": "IP-CIDR,198.51.100.0/24",
		"v6": "IP-CIDR6,2001:db8:2::/48,no-resolve",
	} {
		plain, warnings, err := option.ParseSurgeRuleSet([]byte(text), C.RuleSetFormatSurgeRules)
		require.NoError(t, err)
		require.Empty(t, warnings)
		set, err := NewLocalRuleSet(ctx, log.NewNOPFactory().Logger(), tag, option.RuleSet{Type: C.RuleSetTypeInline, InlineOptions: plain})
		require.NoError(t, err)
		router.ruleSets[tag] = set
		t.Cleanup(func() { require.NoError(t, set.Close()) })
	}

	for _, queryType := range []uint16{0, mDNS.TypeA, mDNS.TypeAAAA, mDNS.TypeTXT} {
		for _, tag := range []string{"v4", "v6"} {
			rule := bboxSurgeDNSRule(t, ctx, fmt.Sprintf(`{"rule_set":[%q],"action":"route","server":"dns"}`, tag), false)
			metadata := adapter.InboundContext{Domain: "lookup.test", QueryType: queryType, RuleMatchContext: ctx}
			require.False(t, rule.Match(&metadata), "an unanswered DNS question has no destination address")
			require.NoError(t, metadata.RuleMatchError)
			require.False(t, metadata.RuleMatchDNSResolved)
			require.False(t, metadata.DNSFlow, "DNS rule scope leaked into connection routing")
			require.True(t, rule.LegacyPreMatch(&metadata), "legacy DNS must defer IP filtering until an answer exists")
			require.True(t, rule.WithAddressLimit())
			require.Zero(t, lookups.Load(), "query matching invoked a nested DNS lookup")
		}
	}

	for _, sample := range []struct {
		name, tag   string
		addresses   []string
		acceptEmpty bool
		want        bool
	}{
		{"second IPv4 answer matches", "v4", []string{"192.0.2.1", "198.51.100.2"}, false, true},
		{"all IPv4 answers miss", "v4", []string{"192.0.2.1", "203.0.113.2"}, false, false},
		{"second IPv6 answer matches with no-resolve", "v6", []string{"2001:db8:1::1", "2001:db8:2::2"}, false, true},
		{"all IPv6 answers miss", "v6", []string{"2001:db8:1::1", "2001:db8:3::2"}, false, false},
		{"empty response rejected by default", "v4", nil, false, false},
		{"legacy empty response accepted", "v4", nil, true, true},
		{"other-family response is not empty", "v4", []string{"2001:db8:1::1"}, true, false},
	} {
		t.Run(sample.name, func(t *testing.T) {
			legacy := bboxSurgeDNSRule(t, ctx, fmt.Sprintf(`{"rule_set":[%q],"rule_set_ip_cidr_accept_empty":%t,"action":"route","server":"dns"}`, sample.tag, sample.acceptEmpty), true)
			metadata := adapter.InboundContext{Domain: "lookup.test", QueryType: mDNS.TypeA, RuleMatchContext: ctx}
			require.True(t, legacy.LegacyPreMatch(&metadata))
			response := bboxSurgeDNSResponse(sample.addresses...)
			require.Equal(t, sample.want, legacy.MatchAddressLimit(&metadata, response))
			if !sample.acceptEmpty {
				modern := bboxSurgeDNSRule(t, ctx, fmt.Sprintf(`{"rule_set":[%q],"match_response":true,"action":"route","server":"dns"}`, sample.tag), false)
				metadata.DNSResponse = response
				require.Equal(t, sample.want, modern.Match(&metadata))
				named := bboxSurgeDNSRule(t, ctx, fmt.Sprintf(`{"rule_set":[%q],"match_response":"answer","action":"route","server":"dns"}`, sample.tag), false)
				metadata.DNSResponse = bboxSurgeDNSResponse("203.0.113.3")
				metadata.NamedDNSResponses = map[string]*mDNS.Msg{"answer": response}
				require.Equal(t, sample.want, named.Match(&metadata), "named response matching used the unrelated anonymous answer")
			}
			require.Zero(t, lookups.Load())
		})
	}

	// A native DNS consumer must not change the Surge connection rule's first
	// address semantics, or leak its matching scope back into the shared set.
	connection := adapter.InboundContext{Destination: M.ParseSocksaddr("lookup.test:443"), DestinationAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2")}, RuleMatchContext: ctx}
	require.False(t, router.ruleSets["v4"].Match(&connection))
	connection.DestinationAddresses[0] = netip.MustParseAddr("198.51.100.2")
	require.True(t, router.ruleSets["v4"].Match(&connection))
	require.Zero(t, lookups.Load())
}

func TestBboxSurgeDNSFlowKeepsHTTPRequestProtocolsUnknown(t *testing.T) {
	t.Parallel()
	router := &addressFilterRouter{ruleSets: make(map[string]adapter.RuleSet)}
	ctx := service.ContextWith[adapter.Router](context.Background(), router)
	for tag, text := range map[string]string{
		"http":        "PROTOCOL,HTTP",
		"https":       "PROTOCOL,HTTPS",
		"not-http":    "NOT,((PROTOCOL,HTTP))",
		"not-https":   "NOT,((PROTOCOL,HTTPS))",
		"http-or-udp": "OR,((PROTOCOL,HTTP),(PROTOCOL,UDP))",
	} {
		plain, warnings, err := option.ParseSurgeRuleSet([]byte(text), C.RuleSetFormatSurgeRules)
		require.NoError(t, err)
		require.Empty(t, warnings)
		set, err := NewLocalRuleSet(ctx, log.NewNOPFactory().Logger(), tag, option.RuleSet{Type: C.RuleSetTypeInline, InlineOptions: plain})
		require.NoError(t, err)
		router.ruleSets[tag] = set
		t.Cleanup(func() { require.NoError(t, set.Close()) })
	}
	for _, sample := range []struct {
		protocol, network, url string
	}{
		{C.ProtocolHTTP, "tcp", "http://origin.test/path"},
		{C.ProtocolHTTP, "tcp", "https://origin.test/path"},
		{C.ProtocolHTTP, "tcp", ""},
		{C.ProtocolQUIC, "udp", "https://origin.test/path"},
	} {
		for _, tag := range []string{"http", "https", "not-http", "not-https", "http-or-udp"} {
			rule := bboxSurgeDNSRule(t, ctx, fmt.Sprintf(`{"rule_set":[%q],"action":"route","server":"dns"}`, tag), false)
			metadata := adapter.InboundContext{Domain: "lookup.test", QueryType: mDNS.TypeA, Network: sample.network, Protocol: sample.protocol, HTTPURL: sample.url, HTTPHost: "origin.test", HTTPServerName: "sni.test", RuleMatchContext: ctx}
			knownWinner := tag == "http-or-udp" && sample.network == "udp"
			require.Equal(t, knownWinner, rule.Match(&metadata), "%s used the original connection's HTTP request while matching DNS", tag)
			require.Equal(t, !knownWinner, metadata.RuleMatchPendingHTTP, "an unknown HTTP predicate was negated or hid a known UDP winner")
			require.False(t, metadata.DNSFlow)
			require.Equal(t, sample.url, metadata.HTTPURL, "temporary DNS scope discarded the connection's HTTP URL")
		}
	}
	// Native DNS protocol conditions describe the query's source connection,
	// and must retain their existing meaning alongside Surge request predicates.
	native := bboxSurgeDNSRule(t, ctx, `{"protocol":"http","action":"route","server":"dns"}`, false)
	metadata := adapter.InboundContext{Domain: "lookup.test", Protocol: C.ProtocolHTTP, HTTPURL: "https://origin.test/path", RuleMatchContext: ctx}
	require.True(t, native.Match(&metadata))
}

func TestBboxSurgeDNSFlowKeepsExtendedDomainAndNOTMatchingNative(t *testing.T) {
	t.Parallel()
	router := &addressFilterRouter{ruleSets: make(map[string]adapter.RuleSet)}
	ctx := service.ContextWith[adapter.Router](context.Background(), router)
	for tag, text := range map[string]string{
		"domains":     "DOMAIN,exact.test,extended-matching\nDOMAIN-SUFFIX,suffix.test\nDOMAIN-KEYWORD,needle\nDOMAIN-WILDCARD,api?.wild.test",
		"not-domains": "NOT,((DOMAIN,exact.test)),extended-matching",
	} {
		plain, warnings, err := option.ParseSurgeRuleSet([]byte(text), C.RuleSetFormatSurgeRules)
		require.NoError(t, err)
		require.Empty(t, warnings)
		set, err := NewLocalRuleSet(ctx, log.NewNOPFactory().Logger(), tag, option.RuleSet{Type: C.RuleSetTypeInline, InlineOptions: plain})
		require.NoError(t, err)
		router.ruleSets[tag] = set
		t.Cleanup(func() { require.NoError(t, set.Close()) })
	}
	positive := bboxSurgeDNSRule(t, ctx, `{"rule_set":"domains","action":"route","server":"dns"}`, false)
	negative := bboxSurgeDNSRule(t, ctx, `{"rule_set":"domains","invert":true,"action":"route","server":"dns"}`, false)
	logicalNOT := bboxSurgeDNSRule(t, ctx, `{"rule_set":"not-domains","action":"route","server":"dns"}`, false)
	for _, sample := range []struct {
		domain string
		want   bool
	}{
		{"exact.test", true},
		{"sub.suffix.test", true},
		{"has-needle.test", true},
		{"api1.wild.test", true},
		{"unmatched.test", false},
	} {
		metadata := adapter.InboundContext{Domain: sample.domain, HTTPHost: "exact.test", HTTPServerName: "exact.test", HTTPExtendedMatching: true, RuleMatchContext: ctx}
		require.Equal(t, sample.want, positive.Match(&metadata))
		require.False(t, metadata.RuleMatchPendingHTTP, "a native DNS domain condition waited for an HTTP request")
		metadata.ResetRuleCache()
		require.Equal(t, !sample.want, negative.Match(&metadata))
		require.False(t, metadata.RuleMatchPendingHTTP)
		metadata.ResetRuleCache()
		require.Equal(t, sample.domain != "exact.test", logicalNOT.Match(&metadata), "Surge NOT domain changed native DNS negation")
		require.False(t, metadata.RuleMatchPendingHTTP)
		require.False(t, metadata.DNSFlow)
	}
	// The same shared set can also be consumed directly by a DNS matcher; its
	// HTTP extension must not consider inherited Host/SNI connection attributes.
	dnsMetadata := adapter.InboundContext{DNSFlow: true, Domain: "unmatched.test", HTTPHost: "exact.test", HTTPServerName: "exact.test", HTTPExtendedMatching: true}
	require.False(t, router.ruleSets["domains"].Match(&dnsMetadata))
	require.False(t, dnsMetadata.RuleMatchPendingHTTP)
	connection := dnsMetadata
	connection.DNSFlow = false
	connection.HTTPURL = "https://unmatched.test/path"
	require.True(t, router.ruleSets["domains"].Match(&connection), "DNS scoping removed extended matching from HTTP connections")
}
