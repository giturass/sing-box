package rule

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/httpdebug"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type scriptRuleDNS struct {
	adapter.DNSRouter
	calls int
	err   error
}

func (d *scriptRuleDNS) Lookup(ctx context.Context, domain string, _ adapter.DNSQueryOptions) ([]netip.Addr, error) {
	d.calls++
	if domain != "api.test" {
		return nil, errors.New("unexpected rule destination")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d.err != nil {
		return nil, d.err
	}
	return []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}, nil
}

func startRuleScriptTest(t *testing.T, source string) (context.Context, *scriptRuleDNS) {
	t.Helper()
	httpdebug.StopService()
	t.Cleanup(httpdebug.StopService)
	prepared, err := httpdebug.PrepareProcessing(t.TempDir(), nil, nil,
		&httpdebug.ScriptsConfig{Enabled: true, Rule: []httpdebug.GenericScript{{Name: "choose", Source: source}}}, "", nil, "UTC")
	if err != nil {
		t.Fatal(err)
	}
	httpdebug.ActivateProcessing(prepared, nil, nil, "")
	dns := &scriptRuleDNS{}
	ctx := service.ContextWithDefaultRegistry(context.Background())
	ctx = service.ContextWith[adapter.DNSRouter](ctx, dns)
	ctx = service.ContextWith(ctx, &httpdebug.ScriptDeclarations{Rule: map[string]bool{"choose": true}})
	return ctx, dns
}

func ruleScriptMetadata(ctx context.Context) adapter.InboundContext {
	return adapter.InboundContext{RuleMatchContext: ctx, Network: "tcp", Protocol: "tls",
		Source: M.ParseSocksaddr("192.0.2.2:12000"), Destination: M.ParseSocksaddr("api.test:443"),
		HTTPURL: "https://api.test/path", HTTPUserAgent: "Mobile"}
}

func TestScriptRuleCacheBelongsToOneRequestAndSharesResolution(t *testing.T) {
	ctx, dns := startRuleScriptTest(t, `
if ($request.hostname !== 'api.test' || $request.protocol !== 'HTTPS' || $request.url !== 'https://api.test/path' ||
    $request.userAgent !== 'Mobile' || $request.dnsResult.v4Addresses[0] !== '192.0.2.1' ||
    $request.dnsResult.v6Addresses[0] !== '2001:db8::1') throw Error('wrong request metadata');
var n=Number($persistentStore.read('condition-runs')||0)+1;
$persistentStore.write(String(n),'condition-runs'); $done({matched:n%2===1});`)
	item, err := NewScriptItem(ctx, "choose", true)
	if err != nil {
		t.Fatal(err)
	}
	metadata := ruleScriptMetadata(ctx)
	if !item.Match(&metadata) {
		t.Fatal("first script evaluation did not match", metadata.RuleMatchError)
	}
	metadata.ResetRuleCache()
	if !item.Match(&metadata) || dns.calls != 1 {
		t.Fatal("per-rule cache reset reran the script or DNS", dns.calls)
	}
	next := ruleScriptMetadata(ctx)
	if item.Match(&next) || dns.calls != 2 {
		t.Fatal("another request reused the old script or DNS result", dns.calls)
	}
	next.ResetRuleCache()
	if item.Match(&next) || dns.calls != 2 {
		t.Fatal("false script results were not cached within the request", dns.calls)
	}
	third := ruleScriptMetadata(ctx)
	if !item.Match(&third) || dns.calls != 3 {
		t.Fatal("third independent evaluation was lost", dns.calls)
	}
}

func TestScriptRuleWithoutRequiresResolveKeepsDNSResultNull(t *testing.T) {
	ctx, dns := startRuleScriptTest(t, `$done({matched: $request.dnsResult === null});`)
	item, err := NewScriptItem(ctx, "choose", false)
	if err != nil {
		t.Fatal(err)
	}
	metadata := ruleScriptMetadata(ctx)
	metadata.RuleMatchDNSResolved = true
	metadata.DestinationAddresses = []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}
	if !item.Match(&metadata) || metadata.RuleMatchError != nil {
		t.Fatal("a script without requires-resolve observed a previous rule's DNS result", metadata.RuleMatchError)
	}
	if dns.calls != 0 {
		t.Fatal("a script without requires-resolve started DNS", dns.calls)
	}
}

func TestScriptRuleLiteralIPDestinationHostname(t *testing.T) {
	for _, test := range []struct{ name, destination, hostname string }{
		{"IPv4", "192.0.2.10:443", "192.0.2.10"},
		{"IPv6", "[2001:db8::10]:443", "2001:db8::10"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, dns := startRuleScriptTest(t, "$done({matched: $request.hostname === "+strconv.Quote(test.hostname)+"});")
			item, err := NewScriptItem(ctx, "choose", false)
			if err != nil {
				t.Fatal(err)
			}
			metadata := adapter.InboundContext{RuleMatchContext: ctx, Network: "tcp", Destination: M.ParseSocksaddr(test.destination)}
			if !item.Match(&metadata) || metadata.RuleMatchError != nil {
				t.Fatal("literal IP destination was not supplied as the script hostname", metadata.RuleMatchError)
			}
			if dns.calls != 0 {
				t.Fatal("literal IP hostname triggered DNS", dns.calls)
			}
		})
	}
}

func TestScriptRuleCachedFalseStillAppliesLaterRequiresResolve(t *testing.T) {
	ctx, dns := startRuleScriptTest(t, `
var n=Number($persistentStore.read('resolution-reference-runs')||0)+1;
$persistentStore.write(String(n),'resolution-reference-runs');
$done({matched:n>1});`)
	plain, err := NewScriptItem(ctx, "choose", false)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := NewScriptItem(ctx, "choose", true)
	if err != nil {
		t.Fatal(err)
	}
	metadata := ruleScriptMetadata(ctx)
	if plain.Match(&metadata) || metadata.RuleMatchError != nil || dns.calls != 0 {
		t.Fatal("first unresolving script reference did not cache false without DNS", metadata.RuleMatchError, dns.calls)
	}
	metadata.ResetRuleCache()
	if resolved.Match(&metadata) || metadata.RuleMatchError != nil || dns.calls != 1 || len(metadata.DestinationAddresses) != 2 {
		t.Fatal("later requires-resolve reference lost DNS or reran the cached script", metadata.RuleMatchError, dns.calls)
	}
	metadata.ResetRuleCache()
	if resolved.Match(&metadata) || metadata.RuleMatchError != nil || dns.calls != 1 {
		t.Fatal("repeated requires-resolve reference reran DNS or JavaScript", metadata.RuleMatchError, dns.calls)
	}
	next := ruleScriptMetadata(ctx)
	if !plain.Match(&next) || next.RuleMatchError != nil || dns.calls != 1 {
		t.Fatal("the next request was not the script's second invocation", next.RuleMatchError, dns.calls)
	}
}

func TestScriptRuleRequiresResolveRespectsNoResolveAndPropagatesDNSFailure(t *testing.T) {
	ctx, dns := startRuleScriptTest(t, `$done({matched:true});`)
	item, err := NewScriptItem(ctx, "choose", true)
	if err != nil {
		t.Fatal(err)
	}
	pre := ruleScriptMetadata(ctx)
	pre.PreMatch = true
	if item.Match(&pre) || dns.calls != 0 || !pre.RuleMatchNeedsResolution {
		t.Fatal("pre-matching performed script DNS", dns.calls)
	}
	noResolve := ruleScriptMetadata(ctx)
	noResolve.SurgeNoResolve = true
	if item.Match(&noResolve) || dns.calls != 0 || noResolve.RuleMatchError != nil {
		t.Fatal("no-resolve did not suppress script resolution", dns.calls)
	}
	dns.err = errors.New("rule DNS failure")
	failed := ruleScriptMetadata(ctx)
	if item.Match(&failed) || !errors.Is(failed.RuleMatchError, dns.err) {
		t.Fatal("failed DNS could select a later route", failed.RuleMatchError)
	}
	if item.Match(&failed) || dns.calls != 1 {
		t.Fatal("a failed request attempted DNS again", dns.calls)
	}
}

func TestScriptRuleValidatesNamesAndStopsOnEngineCancellation(t *testing.T) {
	ctx, _ := startRuleScriptTest(t, `$done({matched:true});`)
	if _, err := NewScriptItem(ctx, "missing", false); err == nil {
		t.Fatal("unknown script bypassed instance validation")
	}
	item, err := NewScriptItem(ctx, "choose", false)
	if err != nil {
		t.Fatal(err)
	}
	httpdebug.Current().Close()
	metadata := ruleScriptMetadata(ctx)
	if item.Match(&metadata) || !errors.Is(metadata.RuleMatchError, context.Canceled) {
		t.Fatal("engine shutdown silently selected the next rule", metadata.RuleMatchError)
	}
}
