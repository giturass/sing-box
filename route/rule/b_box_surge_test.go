package rule

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/httpdebug"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func TestBboxSurgeRuleSetTextFormatsAndAtomicLogicalParsing(t *testing.T) {
	set, warnings, err := option.ParseSurgeRuleSet([]byte("# rules\nDOMAIN,exact.test\nAND,((DOMAIN-SUFFIX,example.test),(URL-REGEX,(?<=/path/)secret))\nUSER-AGENT,App?/*\nOR,((DOMAIN,unsafe.test),(UNSUPPORTED,anything))\nRULE-SET,nested.txt\nFINAL,DIRECT\n"), C.RuleSetFormatSurgeRules)
	require.NoError(t, err)
	require.Len(t, set.Rules, 3)
	require.Len(t, warnings, 3)
	for _, raw := range set.Rules {
		rule, err := NewHeadlessRule(context.Background(), raw)
		require.NoError(t, err)
		unsafe := adapter.InboundContext{Domain: "unsafe.test", HTTPURL: "https://unsafe.test/", HTTPUserAgent: "Other"}
		require.False(t, rule.Match(&unsafe), "an unsupported logical child widened its complete rule")
	}
	domains, warnings, err := option.ParseSurgeRuleSet([]byte("// domains\nexact.test\n.suffix.test\n*.unsupported.test\nDOMAIN,not-a-domain.test\n"), C.RuleSetFormatSurgeDomains)
	require.NoError(t, err)
	require.Len(t, domains.Rules, 2)
	require.Len(t, warnings, 2)
	exact, err := NewHeadlessRule(context.Background(), domains.Rules[0])
	require.NoError(t, err)
	require.True(t, exact.Match(&adapter.InboundContext{Domain: "exact.test"}))
	require.False(t, exact.Match(&adapter.InboundContext{Domain: "sub.exact.test"}))
	suffix, err := NewHeadlessRule(context.Background(), domains.Rules[1])
	require.NoError(t, err)
	require.True(t, suffix.Match(&adapter.InboundContext{Domain: "suffix.test"}))
	require.True(t, suffix.Match(&adapter.InboundContext{Domain: "sub.suffix.test"}))
	_, _, err = option.ParseSurgeRuleSet([]byte(`{"version":3,"rules":[{"domain":"example.test"}]}`), C.RuleSetFormatSurgeRules)
	require.Error(t, err, "a Surge resource must not be guessed as sing-box JSON")
}

func TestBboxSurgeRuleSetCommentsRemainFormatSpecific(t *testing.T) {
	rules, warnings, err := option.ParseSurgeRuleSet([]byte("# first\n// second\n  ; third\nDOMAIN,example.test"), C.RuleSetFormatSurgeRules)
	require.NoError(t, err)
	require.Empty(t, warnings)
	require.Len(t, rules.Rules, 1)
	rules, warnings, err = option.ParseSurgeRuleSet([]byte("  ; comment only"), C.RuleSetFormatSurgeRules)
	require.NoError(t, err)
	require.Empty(t, warnings)
	require.Empty(t, rules.Rules)
	domains, warnings, err := option.ParseSurgeRuleSet([]byte("# first\n// second\n; not a DOMAIN-SET comment\nexample.test"), C.RuleSetFormatSurgeDomains)
	require.NoError(t, err)
	require.Len(t, domains.Rules, 1)
	require.Len(t, warnings, 1)
	require.Equal(t, 3, warnings[0].Line)
}

func TestBboxSurgeDomainWildcardCharacterClassesMatchAndRejectAmbiguity(t *testing.T) {
	for _, sample := range []struct {
		pattern         string
		matches, misses []string
	}{
		{"cdn[0-9].example.test", []string{"cdn0.example.test", "CDN7.EXAMPLE.TEST"}, []string{"cdnx.example.test", "cdn12.example.test", "cdn[0-9].example.test"}},
		{"api[ab]?.example.test", []string{"apia1.example.test", "apibx.example.test"}, []string{"apic1.example.test", "apia.example.test"}},
		{"srv[-ab].example.test", []string{"srv-.example.test", "srva.example.test", "srvb.example.test"}, []string{"srvc.example.test"}},
		{"srv[ab-].example.test", []string{"srv-.example.test", "srva.example.test"}, []string{"srvc.example.test"}},
		{"cdn[0-9][a-c]*.example.test", []string{"cdn3a.example.test", "cdn7bassets.example.test"}, []string{"cdn7dassets.example.test", "cdnaa.example.test"}},
	} {
		set, warnings, err := option.ParseSurgeRuleSet([]byte("DOMAIN-WILDCARD,"+sample.pattern), C.RuleSetFormatSurgeRules)
		require.NoError(t, err)
		require.Empty(t, warnings)
		require.Len(t, set.Rules, 1)
		rule, err := NewHeadlessRule(context.Background(), set.Rules[0])
		require.NoError(t, err)
		for _, domain := range sample.matches {
			require.True(t, rule.Match(&adapter.InboundContext{Domain: domain}), "%s must match %s", sample.pattern, domain)
		}
		for _, domain := range sample.misses {
			require.False(t, rule.Match(&adapter.InboundContext{Domain: domain}), "%s must not match %s", sample.pattern, domain)
		}
	}
	for _, pattern := range []string{"cdn[].example.test", "cdn[0-9.example.test", "cdn].example.test", "cdn[9-0].example.test", "cdn[^a].example.test", "cdn[!a].example.test", "cdn[[:digit:]].example.test", `cdn[a\-c].example.test`, "cdn[a-b-c].example.test"} {
		_, err := option.ParseSurgeRule("DOMAIN-WILDCARD,"+pattern+",DIRECT", true)
		require.Error(t, err, pattern)
	}
	set, warnings, err := option.ParseSurgeRuleSet([]byte("DOMAIN,safe.test\nOR,((DOMAIN,unsafe.test),(DOMAIN-WILDCARD,cdn[9-0].example.test))"), C.RuleSetFormatSurgeRules)
	require.NoError(t, err)
	require.Len(t, set.Rules, 1)
	require.Len(t, warnings, 1)
	rule, err := NewHeadlessRule(context.Background(), set.Rules[0])
	require.NoError(t, err)
	require.False(t, rule.Match(&adapter.InboundContext{Domain: "unsafe.test"}), "invalid wildcard child widened its containing logical rule")
}

type bboxSurgeDNS struct {
	adapter.DNSRouter
	lookup func(context.Context, string) ([]netip.Addr, error)
}

func (d *bboxSurgeDNS) Lookup(ctx context.Context, domain string, _ adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return d.lookup(ctx, domain)
}

func TestBboxSurgeIPRulesResolveOnceAndUseFirstAddressOfFamily(t *testing.T) {
	var calls atomic.Int32
	dns := &bboxSurgeDNS{lookup: func(context.Context, string) ([]netip.Addr, error) {
		calls.Add(1)
		return []netip.Addr{netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("2001:db8:2::1")}, nil
	}}
	ctx := service.ContextWith[adapter.DNSRouter](context.Background(), dns)
	first4, err := NewSurgeIPCIDRItem(ctx, parsePrefixables([]string{"192.0.2.0/24"}), false)
	require.NoError(t, err)
	second4, err := NewSurgeIPCIDRItem(ctx, parsePrefixables([]string{"198.51.100.0/24"}), false)
	require.NoError(t, err)
	first6, err := NewSurgeIPCIDRItem(ctx, parsePrefixables([]string{"2001:db8:1::/48"}), false)
	require.NoError(t, err)
	second6, err := NewSurgeIPCIDRItem(ctx, parsePrefixables([]string{"2001:db8:2::/48"}), false)
	require.NoError(t, err)
	metadata := adapter.InboundContext{Destination: M.ParseSocksaddr("lookup.test:443"), RuleMatchContext: ctx}
	require.True(t, first4.Match(&metadata))
	require.True(t, first6.Match(&metadata))
	require.False(t, second4.Match(&metadata))
	require.False(t, second6.Match(&metadata))
	require.Equal(t, int32(1), calls.Load())
	native, err := NewIPCIDRItem(false, parsePrefixables([]string{"198.51.100.0/24"}))
	require.NoError(t, err)
	require.True(t, native.Match(&metadata), "native sing-box matching must retain any-address behavior")
	noResolve, err := NewSurgeIPCIDRItem(ctx, parsePrefixables([]string{"192.0.2.0/24"}), true)
	require.NoError(t, err)
	unknown := adapter.InboundContext{Destination: M.ParseSocksaddr("unknown.test:443"), RuleMatchContext: ctx}
	require.False(t, noResolve.Match(&unknown))
	require.Equal(t, int32(1), calls.Load())
	require.True(t, noResolve.Match(&metadata), "no-resolve must still use an existing DNS result")
	unknown.PreMatch = true
	require.False(t, first4.Match(&unknown))
	require.True(t, unknown.RuleMatchNeedsResolution)
	require.Equal(t, int32(1), calls.Load(), "flow pre-match must not perform a blocking DNS lookup")
}

func TestBboxSurgeIPResolutionCancellationDoesNotFallThrough(t *testing.T) {
	entered := make(chan struct{})
	dns := &bboxSurgeDNS{lookup: func(ctx context.Context, _ string) ([]netip.Addr, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	ctx, cancel := context.WithCancel(service.ContextWith[adapter.DNSRouter](context.Background(), dns))
	item, err := NewSurgeIPCIDRItem(ctx, parsePrefixables([]string{"192.0.2.0/24"}), false)
	require.NoError(t, err)
	metadata := adapter.InboundContext{Destination: M.ParseSocksaddr("cancel.test:443"), RuleMatchContext: ctx}
	done := make(chan bool, 1)
	go func() { done <- item.Match(&metadata) }()
	<-entered
	cancel()
	select {
	case matched := <-done:
		require.False(t, matched)
	case <-time.After(time.Second):
		t.Fatal("Surge IP lookup ignored cancellation")
	}
	require.ErrorIs(t, metadata.RuleMatchError, context.Canceled)
}

func TestBboxSurgeRuleSetOuterModifiersAreScoped(t *testing.T) {
	ctx := context.Background()
	set, err := NewLocalRuleSet(ctx, logger.NOP(), "domains", option.RuleSet{Type: C.RuleSetTypeInline, InlineOptions: option.PlainRuleSet{Rules: []option.HeadlessRule{{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{Domain: []string{"target.test"}}}}}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = set.Close() })
	ctx = service.ContextWith[adapter.Router](ctx, &ruleSetItemTestRouter{ruleSets: map[string]adapter.RuleSet{"domains": set}})
	outer, err := NewDefaultRule(ctx, logger.NOP(), option.DefaultRule{RawDefaultRule: option.RawDefaultRule{RuleSet: []string{"domains"}, HTTPExtendedMatching: true}})
	require.NoError(t, err)
	require.NoError(t, outer.Start())
	t.Cleanup(func() { _ = outer.Close() })
	metadata := adapter.InboundContext{Domain: "original.test", Destination: M.ParseSocksaddr("original.test:443"), HTTPURL: "https://original.test/path?q=1", HTTPHost: "target.test:9443", HTTPServerName: "sni.test"}
	require.True(t, outer.Match(&metadata))
	require.False(t, metadata.HTTPExtendedMatching)
	require.False(t, set.Match(&metadata), "extended matching leaked to an unrelated rule")
	metadata.HTTPExtendedMatching = true
	require.True(t, set.Match(&metadata))
	urls := HTTPRequestURLs(&metadata)
	require.Contains(t, urls, "https://target.test/path?q=1")
	require.Contains(t, urls, "https://sni.test/path?q=1")
	require.NotContains(t, urls, "https://target.test:9443/path?q=1", "extended matching must preserve the original URL port")
	metadata.HTTPURL = "https://original.test:8443/path?q=1"
	require.Contains(t, HTTPRequestURLs(&metadata), "https://target.test:8443/path?q=1")
	negated, err := NewDefaultHeadlessRule(ctx, option.DefaultHeadlessRule{Domain: []string{"target.test"}, HTTPExtendedMatching: true, Invert: true})
	require.NoError(t, err)
	unknown := adapter.InboundContext{Domain: "original.test"}
	require.False(t, negated.Match(&unknown))
	require.True(t, unknown.RuleMatchPendingHTTP)
	var lookups atomic.Int32
	dns := &bboxSurgeDNS{lookup: func(context.Context, string) ([]netip.Addr, error) {
		lookups.Add(1)
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	}}
	ctx = service.ContextWith[adapter.DNSRouter](ctx, dns)
	ips, err := NewLocalRuleSet(ctx, logger.NOP(), "ips", option.RuleSet{Type: C.RuleSetTypeInline, InlineOptions: option.PlainRuleSet{Rules: []option.HeadlessRule{{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{IPCIDR: parsePrefixables([]string{"192.0.2.0/24"}), SurgeIPCIDR: true}}}}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ips.Close() })
	ctx = service.ContextWith[adapter.Router](ctx, &ruleSetItemTestRouter{ruleSets: map[string]adapter.RuleSet{"ips": ips}})
	noResolve, err := NewDefaultRule(ctx, logger.NOP(), option.DefaultRule{RawDefaultRule: option.RawDefaultRule{RuleSet: []string{"ips"}, SurgeNoResolve: true}})
	require.NoError(t, err)
	resolve, err := NewDefaultRule(ctx, logger.NOP(), option.DefaultRule{RawDefaultRule: option.RawDefaultRule{RuleSet: []string{"ips"}}})
	require.NoError(t, err)
	require.NoError(t, noResolve.Start())
	require.NoError(t, resolve.Start())
	t.Cleanup(func() { _ = noResolve.Close(); _ = resolve.Close() })
	lookup := adapter.InboundContext{Destination: M.ParseSocksaddr("lookup.test:443"), RuleMatchContext: ctx}
	require.False(t, noResolve.Match(&lookup))
	require.Equal(t, int32(0), lookups.Load())
	require.False(t, lookup.SurgeNoResolve)
	require.True(t, resolve.Match(&lookup))
	require.Equal(t, int32(1), lookups.Load())
	require.False(t, lookup.SurgeNoResolve)
	require.True(t, noResolve.Match(&lookup), "outer no-resolve must still use already resolved addresses")
}

func TestBboxSurgeConditionsCannotDisappearDuringBinaryExport(t *testing.T) {
	for _, rule := range []option.DefaultHeadlessRule{
		{HTTPURLRegex: []string{"/private"}}, {HTTPUserAgent: []string{"App*"}}, {Script: "route"},
		{IPCIDR: parsePrefixables([]string{"192.0.2.0/24"}), SurgeIPCIDR: true},
		{Domain: []string{"example.test"}, HTTPExtendedMatching: true},
		{SurgeProtocol: []string{"HTTPS"}}, {Protocol: []string{"http"}},
	} {
		var output bytes.Buffer
		err := srs.Write(&output, option.PlainRuleSet{Rules: []option.HeadlessRule{{Type: C.RuleTypeLogical, LogicalOptions: option.LogicalHeadlessRule{Mode: C.LogicalTypeAnd, Rules: []option.HeadlessRule{{Type: C.RuleTypeDefault, DefaultOptions: rule}}}}}}, C.RuleSetVersionCurrent)
		require.ErrorContains(t, err, "cannot be represented")
	}
}

func TestBboxSurgeExtendedDomainKnownMatchesDoNotWaitForHTTP(t *testing.T) {
	for _, options := range []option.DefaultHeadlessRule{
		{Domain: []string{"api.example.test"}, HTTPExtendedMatching: true},
		{DomainSuffix: []string{"example.test"}, HTTPExtendedMatching: true},
		{DomainKeyword: []string{"example"}, HTTPExtendedMatching: true},
		{DomainRegex: []string{`^api\.example\.test$`}, HTTPExtendedMatching: true},
		{Domain: []string{"unknown.test"}, DomainKeyword: []string{"example"}, HTTPExtendedMatching: true},
		{Domain: []string{"unknown.test"}, IPCIDR: parsePrefixables([]string{"192.0.2.0/24"}), HTTPExtendedMatching: true},
		{Domain: []string{"unknown.test"}, IPCIDR: parsePrefixables([]string{"192.0.2.0/24"}), SurgeIPCIDR: true, HTTPExtendedMatching: true},
	} {
		metadata := adapter.InboundContext{Domain: "api.example.test", Destination: M.ParseSocksaddr("192.0.2.1:22"), Network: "tcp", Protocol: "ssh"}
		rule, err := NewDefaultHeadlessRule(context.Background(), options)
		require.NoError(t, err)
		require.True(t, rule.Match(&metadata))
		require.False(t, metadata.RuleMatchPendingHTTP)
		options.Invert = true
		negated, err := NewDefaultHeadlessRule(context.Background(), options)
		require.NoError(t, err)
		require.False(t, negated.Match(&metadata))
		require.False(t, metadata.RuleMatchPendingHTTP)
	}
}

type bboxSurgeRoundTrip func(*http.Request) (*http.Response, error)

func (f bboxSurgeRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
func bboxSurgeResponse(text string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(text))}
}

func bboxSurgeRelease(channel chan struct{}) {
	select {
	case <-channel:
	default:
		close(channel)
	}
}

type bboxSurgeCache struct {
	adapter.CacheFile
	access sync.Mutex
	saved  map[string]*adapter.SavedBinary
	fail   bool
}

func (c *bboxSurgeCache) LoadRuleSet(tag string) *adapter.SavedBinary {
	c.access.Lock()
	defer c.access.Unlock()
	return bboxSurgeCopySaved(c.saved[tag])
}
func (c *bboxSurgeCache) SaveRuleSet(tag string, set *adapter.SavedBinary) error {
	c.access.Lock()
	defer c.access.Unlock()
	if c.fail {
		return fmt.Errorf("cache commit failed")
	}
	if c.saved == nil {
		c.saved = map[string]*adapter.SavedBinary{}
	}
	c.saved[tag] = bboxSurgeCopySaved(set)
	return nil
}
func bboxSurgeCopySaved(set *adapter.SavedBinary) *adapter.SavedBinary {
	if set == nil {
		return nil
	}
	copy := *set
	copy.Content = bytes.Clone(set.Content)
	copy.URLHash = bytes.Clone(set.URLHash)
	return &copy
}
func bboxSurgeRemote(t *testing.T, tag string, transport http.RoundTripper) *RemoteRuleSet {
	t.Helper()
	set, err := NewRemoteRuleSet(context.Background(), logger.NOP(), tag, option.RuleSet{Type: C.RuleSetTypeRemote, Format: C.RuleSetFormatSurgeRules, RemoteOptions: option.RemoteRuleSet{URL: "https://rules.test/" + tag}})
	require.NoError(t, err)
	set.httpClient = &http.Client{Transport: transport}
	set.IncRef()
	t.Cleanup(func() { _ = set.Close() })
	return set
}

func TestBboxSurgeRemoteCloseWaitsForDelayedDownloadAndKeepsCache(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	defer bboxSurgeRelease(release)
	var requests atomic.Int32
	set := bboxSurgeRemote(t, "delayed", bboxSurgeRoundTrip(func(*http.Request) (*http.Response, error) {
		if requests.Add(1) == 1 {
			return bboxSurgeResponse("DOMAIN,old.test"), nil
		}
		close(entered)
		<-release
		return bboxSurgeResponse("DOMAIN,new.test"), nil
	}))
	cache := &bboxSurgeCache{}
	set.cacheFile = cache
	var callbacks atomic.Int32
	set.RegisterCallback(func(adapter.RuleSet) { callbacks.Add(1) })
	require.NoError(t, set.fetch(context.Background(), true))
	download := make(chan error, 1)
	go func() { download <- set.fetch(context.Background(), false) }()
	<-entered
	closed := make(chan struct{})
	go func() { _ = set.Close(); close(closed) }()
	require.Eventually(t, func() bool { set.access.Lock(); defer set.access.Unlock(); return set.closed }, time.Second, time.Millisecond)
	select {
	case <-closed:
		t.Fatal("Close returned before the admitted download exited")
	default:
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not join the delayed download")
	}
	require.ErrorIs(t, <-download, context.Canceled)
	require.Equal(t, int32(1), callbacks.Load())
	require.Equal(t, "DOMAIN,old.test", string(cache.LoadRuleSet(set.tag).Content))
	require.False(t, set.Match(&adapter.InboundContext{Domain: "new.test"}))
	require.ErrorIs(t, set.loadBytes([]byte("DOMAIN,new.test")), context.Canceled)
}

func TestBboxSurgeRemoteRefreshFailureKeepsLastUsableRules(t *testing.T) {
	var requests atomic.Int32
	set := bboxSurgeRemote(t, "failures", bboxSurgeRoundTrip(func(*http.Request) (*http.Response, error) {
		switch requests.Add(1) {
		case 1:
			return bboxSurgeResponse("DOMAIN,old.test"), nil
		case 2:
			return bboxSurgeResponse("DOMAIN,new.test"), nil
		default:
			return bboxSurgeResponse(`{"version":3,"rules":[]}`), nil
		}
	}))
	cache := &bboxSurgeCache{}
	set.cacheFile = cache
	require.NoError(t, set.fetch(context.Background(), true))
	cache.access.Lock()
	cache.fail = true
	cache.access.Unlock()
	require.ErrorContains(t, set.fetch(context.Background(), false), "cache commit failed")
	require.True(t, set.Match(&adapter.InboundContext{Domain: "old.test"}))
	require.False(t, set.Match(&adapter.InboundContext{Domain: "new.test"}))
	require.Error(t, set.fetch(context.Background(), false))
	require.Equal(t, "DOMAIN,old.test", string(cache.LoadRuleSet(set.tag).Content))
	require.True(t, set.Match(&adapter.InboundContext{Domain: "old.test"}))
}

type bboxSurgeWaitingCache struct {
	bboxSurgeCache
	entered, release chan struct{}
	writes           atomic.Int32
}

func (c *bboxSurgeWaitingCache) SaveRuleSet(tag string, saved *adapter.SavedBinary) error {
	if c.writes.Add(1) == 2 {
		close(c.entered)
		<-c.release
	}
	return c.bboxSurgeCache.SaveRuleSet(tag, saved)
}

func TestBboxSurgeRemoteCloseSerializesCacheCommitAndWaitsForCallbacks(t *testing.T) {
	cache := &bboxSurgeWaitingCache{entered: make(chan struct{}), release: make(chan struct{})}
	defer bboxSurgeRelease(cache.release)
	var requests, callbacks atomic.Int32
	set := bboxSurgeRemote(t, "committing", bboxSurgeRoundTrip(func(*http.Request) (*http.Response, error) {
		if requests.Add(1) == 1 {
			return bboxSurgeResponse("DOMAIN,old.test"), nil
		}
		return bboxSurgeResponse("DOMAIN,new.test"), nil
	}))
	set.cacheFile = cache
	set.RegisterCallback(func(adapter.RuleSet) { callbacks.Add(1) })
	require.NoError(t, set.fetch(context.Background(), true))
	download := make(chan error, 1)
	go func() { download <- set.fetch(context.Background(), false) }()
	<-cache.entered
	closed := make(chan struct{})
	closeStarted := make(chan struct{})
	go func() { close(closeStarted); _ = set.Close(); close(closed) }()
	<-closeStarted
	select {
	case <-closed:
		t.Fatal("Close returned while cache commit was in progress")
	case <-time.After(10 * time.Millisecond):
	}
	close(cache.release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not wait for the cache commit")
	}
	require.NoError(t, <-download)
	require.Equal(t, int32(2), callbacks.Load())
	require.Equal(t, "DOMAIN,new.test", string(cache.LoadRuleSet(set.tag).Content), "a valid commit admitted before Close must complete as one update")
	require.False(t, set.Match(&adapter.InboundContext{Domain: "new.test"}))
	require.ErrorIs(t, set.fetch(context.Background(), false), context.Canceled)
	require.Equal(t, int32(2), cache.writes.Load(), "a closed set admitted a later cache write")
}

func TestBboxSurgeRemoteNotModifiedHonorsCancellation(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	defer bboxSurgeRelease(release)
	set := bboxSurgeRemote(t, "not-modified", bboxSurgeRoundTrip(func(*http.Request) (*http.Response, error) {
		close(entered)
		<-release
		response := bboxSurgeResponse("")
		response.StatusCode = http.StatusNotModified
		return response, nil
	}))
	cache := &bboxSurgeCache{}
	updated := time.Unix(100, 0)
	require.NoError(t, cache.SaveRuleSet(set.tag, &adapter.SavedBinary{Content: []byte("DOMAIN,old.test"), LastUpdated: updated, URLHash: set.urlHash[:]}))
	set.cacheFile, set.lastUpdated = cache, updated
	download := make(chan error, 1)
	go func() { download <- set.fetch(context.Background(), false) }()
	<-entered
	closed := make(chan struct{})
	go func() { _ = set.Close(); close(closed) }()
	require.Eventually(t, func() bool { set.access.Lock(); defer set.access.Unlock(); return set.closed }, time.Second, time.Millisecond)
	close(release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not join the cancelled 304 response")
	}
	require.ErrorIs(t, <-download, context.Canceled)
	require.Equal(t, updated, cache.LoadRuleSet(set.tag).LastUpdated)
}

type bboxSurgeRuleSetValidator struct{ entered, release chan struct{} }

func (v *bboxSurgeRuleSetValidator) ValidateRuleSetMetadataUpdate(string, adapter.RuleSetMetadata) error {
	close(v.entered)
	<-v.release
	return nil
}

func TestBboxSurgeLocalCloseJoinsDeferredStartupWithoutStartingWatcher(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.txt")
	require.NoError(t, os.WriteFile(path, []byte("DOMAIN,example.test"), 0o600))
	validator := &bboxSurgeRuleSetValidator{entered: make(chan struct{}), release: make(chan struct{})}
	defer bboxSurgeRelease(validator.release)
	ctx := service.ContextWith[adapter.DNSRuleSetUpdateValidator](context.Background(), validator)
	set, err := NewLocalRuleSet(ctx, logger.NOP(), "local", option.RuleSet{Type: C.RuleSetTypeLocal, Format: C.RuleSetFormatSurgeRules, LocalOptions: option.LocalRuleSet{Path: path}})
	require.NoError(t, err)
	require.Empty(t, set.Metadata(), "configuration checking opened the deferred local resource")
	started := make(chan error, 1)
	go func() { started <- set.StartContext(ctx, nil) }()
	<-validator.entered
	closed := make(chan struct{})
	go func() { _ = set.Close(); close(closed) }()
	require.Eventually(t, func() bool { set.access.Lock(); defer set.access.Unlock(); return set.closed }, time.Second, time.Millisecond)
	select {
	case <-closed:
		t.Fatal("Close returned before an admitted startup finished")
	default:
	}
	close(validator.release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not join the deferred startup")
	}
	require.ErrorIs(t, <-started, context.Canceled)
	require.Nil(t, set.watcher)
	require.False(t, set.Match(&adapter.InboundContext{Domain: "example.test"}))
	require.ErrorIs(t, set.StartContext(ctx, nil), context.Canceled)
}

func TestBboxSurgeRuleSetSourcesUpdateIndependentlyAndStopTogether(t *testing.T) {
	blockedStarted, blockedCancelled, fastUpdated := make(chan struct{}), make(chan struct{}), make(chan struct{})
	blocked := bboxSurgeRemote(t, "blocked", bboxSurgeRoundTrip(func(request *http.Request) (*http.Response, error) {
		close(blockedStarted)
		<-request.Context().Done()
		close(blockedCancelled)
		return nil, request.Context().Err()
	}))
	fast := bboxSurgeRemote(t, "fast", bboxSurgeRoundTrip(func(*http.Request) (*http.Response, error) { return bboxSurgeResponse("DOMAIN,fast.test"), nil }))
	require.NoError(t, blocked.loadBytes([]byte("DOMAIN,old.test")))
	fast.RegisterCallback(func(adapter.RuleSet) { close(fastUpdated) })
	updater := NewRuleSetUpdater(context.Background(), []adapter.RuleSet{blocked, fast})
	require.NotNil(t, updater)
	updater.Start()
	select {
	case <-blockedStarted:
	case <-time.After(time.Second):
		t.Fatal("blocked source never started")
	}
	select {
	case <-fastUpdated:
	case <-time.After(time.Second):
		t.Fatal("one stalled source blocked another source's refresh")
	}
	require.True(t, fast.Match(&adapter.InboundContext{Domain: "fast.test"}))
	stopped := make(chan struct{})
	go func() { _ = updater.Close(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("rule-set updater did not cancel and join its downloads")
	}
	select {
	case <-blockedCancelled:
	default:
		t.Fatal("updater returned before the blocked source observed cancellation")
	}
	require.True(t, blocked.Match(&adapter.InboundContext{Domain: "old.test"}))
}

func TestBboxSurgeRuleSetCacheIdentityIncludesExplicitFormat(t *testing.T) {
	options := option.RuleSet{Type: C.RuleSetTypeRemote, Format: C.RuleSetFormatSurgeRules, RemoteOptions: option.RemoteRuleSet{URL: "https://rules.test/same", UpdateInterval: badoption.Duration(-time.Second)}}
	rules, err := NewRemoteRuleSet(context.Background(), logger.NOP(), "rules", options)
	require.NoError(t, err)
	defer rules.Close()
	options.Format = C.RuleSetFormatSurgeDomains
	domains, err := NewRemoteRuleSet(context.Background(), logger.NOP(), "domains", options)
	require.NoError(t, err)
	defer domains.Close()
	require.NotEqual(t, rules.urlHash, domains.urlHash)
	require.Nil(t, NewRuleSetUpdater(context.Background(), []adapter.RuleSet{rules, domains}), "negative Surge update interval must disable refresh")
	require.True(t, rules.updatesDisabled)
}

func TestBboxSurgeRemoteScriptNamespaceUsesDeclaredModuleOrProfileName(t *testing.T) {
	ctx := service.ContextWith(context.Background(), &httpdebug.ScriptDeclarations{Rule: map[string]bool{"module/shared": true, "shared": true, "base": true}})
	options := option.RuleSet{Type: C.RuleSetTypeRemote, Format: C.RuleSetFormatSurgeRules, RemoteOptions: option.RemoteRuleSet{URL: "https://rules.test/scripts", ScriptNamespace: "module/"}}
	set, err := NewRemoteRuleSet(ctx, logger.NOP(), "scripts", options)
	require.NoError(t, err)
	t.Cleanup(func() { _ = set.Close() })
	content, err := set.parseBytes([]byte("SCRIPT,shared\nAND,((DOMAIN,example.test),(SCRIPT,base))"))
	require.NoError(t, err)
	require.Contains(t, content.String(), "script=module/shared")
	require.Contains(t, content.String(), "script=base")
	require.NotContains(t, content.String(), "script=module/base")
	_, err = set.parseBytes([]byte("SCRIPT,absent"))
	require.ErrorContains(t, err, "not configured")
	_, err = set.parseBytes([]byte("SCRIPT,module/absent"))
	require.ErrorContains(t, err, "not configured")
}

func TestBboxSurgeRuleSetResourcesCannotHaveConflictingTextFormats(t *testing.T) {
	sets := []option.RuleSet{
		{Type: C.RuleSetTypeRemote, Tag: []string{"rules"}, Format: C.RuleSetFormatSurgeRules, RemoteOptions: option.RemoteRuleSet{URL: "https://rules.test/shared"}},
		{Type: C.RuleSetTypeRemote, Tag: []string{"domains"}, Format: C.RuleSetFormatSurgeDomains, RemoteOptions: option.RemoteRuleSet{URL: "https://rules.test/shared"}},
	}
	require.ErrorContains(t, ValidateSurgeRuleSetResourceFormats(context.Background(), sets), "both RULE-SET and DOMAIN-SET")
	sets[1].RemoteOptions.URL = "https://rules.test/another"
	require.NoError(t, ValidateSurgeRuleSetResourceFormats(context.Background(), sets))
	sets[0].Type, sets[1].Type = C.RuleSetTypeLocal, C.RuleSetTypeLocal
	sets[0].LocalOptions.Path, sets[1].LocalOptions.Path = "rules/shared.txt", "rules/../rules/shared.txt"
	require.ErrorContains(t, ValidateSurgeRuleSetResourceFormats(context.Background(), sets), "both RULE-SET and DOMAIN-SET")
	sets[1].Format = C.RuleSetFormatSource
	require.NoError(t, ValidateSurgeRuleSetResourceFormats(context.Background(), sets), "explicit sing-box source remains an independent compatibility format")
}

func TestBboxSurgeProtocolsRetainOriginalHTTPURLAndNetwork(t *testing.T) {
	for _, sample := range []struct {
		metadata adapter.InboundContext
		want     []string
	}{
		{adapter.InboundContext{Network: "tcp", Protocol: "http", HTTPURL: "http://example.test/"}, []string{"HTTP", "TCP"}},
		{adapter.InboundContext{Network: "tcp", Protocol: "tls", HTTPURL: "https://example.test/"}, []string{"HTTPS", "TCP"}},
		{adapter.InboundContext{Network: "udp", Protocol: "quic", HTTPURL: "https://example.test/"}, []string{"HTTPS", "UDP", "QUIC"}},
		{adapter.InboundContext{Network: "udp", Protocol: "stun"}, []string{"UDP", "STUN"}},
		{adapter.InboundContext{Network: "tcp", Protocol: "tls"}, []string{"TCP"}},
	} {
		for _, value := range []string{"HTTP", "HTTPS", "TCP", "UDP", "QUIC", "STUN"} {
			item, err := NewSurgeProtocolItem([]string{value})
			require.NoError(t, err)
			metadata := sample.metadata
			require.Equal(t, slices.Contains(sample.want, value), item.Match(&metadata), "%s in %+v", value, sample.metadata)
			metadata = sample.metadata
			metadata.PreMatch = true
			require.False(t, item.Match(&metadata))
			require.True(t, metadata.RuleMatchNeedsResolution)
		}
	}
	for _, value := range []string{"http", "TLS", "DNS", "DOH", "DOH3", "DOQ", "DOT", "MTProto"} {
		_, err := option.ParseSurgeRule("PROTOCOL,"+value+",DIRECT", true)
		require.Error(t, err)
		_, err = NewSurgeProtocolItem([]string{value})
		require.Error(t, err)
	}
	parsed, err := option.ParseSurgeRule("PROTOCOL,HTTPS,DIRECT", true)
	require.NoError(t, err)
	require.Equal(t, "HTTPS", parsed.Rule["surge_protocol"])
	negated, err := NewDefaultHeadlessRule(context.Background(), option.DefaultHeadlessRule{SurgeProtocol: []string{"HTTPS"}, Invert: true})
	require.NoError(t, err)
	metadata := adapter.InboundContext{Network: "tcp", Protocol: "tls"}
	require.False(t, negated.Match(&metadata))
	require.True(t, metadata.RuleMatchPendingHTTP)
}
