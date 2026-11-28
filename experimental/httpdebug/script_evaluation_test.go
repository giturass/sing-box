package httpdebug

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/dop251/goja"
)

func activateEvaluationScripts(t *testing.T, directory string, scripts *ScriptsConfig, hosts []DNSHost) *PreparedProcessing {
	t.Helper()
	prepared, err := PrepareProcessing(directory, nil, nil, scripts, "", nil, "UTC", ProcessingConfig{DNSHosts: hosts})
	if err != nil {
		t.Fatal(err)
	}
	ActivateProcessing(prepared, nil, nil, "")
	return prepared
}

func evaluationStoredCount(t *testing.T, key string) string {
	t.Helper()
	value, found, err := Current().scripts.storage.read(context.Background(), "default", key)
	if err != nil || !found {
		t.Fatal("missing script side effect", value, err)
	}
	return value
}

func TestRuleScriptsUseEachRequestsObservedMetadata(t *testing.T) {
	directory := isolateScriptService(t)
	source := `if ($script.type !== 'rule' || typeof $domain !== 'undefined' || typeof $response !== 'undefined') throw Error('context');
if ($request.hostname !== 'api.example.test' || $request.destPort !== 443 || $request.sourcePort !== 12000 ||
$request.sourceIP !== '192.0.2.2' || $request.processPath !== null || $request.listenPort !== null ||
$request.protocol !== 'HTTPS' || $request.dnsResult.v4Addresses[0] !== '192.0.2.1' || $request.dnsResult.v6Addresses[0] !== '2001:db8::1') throw Error('metadata');
var runs = Number($persistentStore.read('rule-runs') || 0) + 1; $persistentStore.write(String(runs), 'rule-runs');
var vmRuns = (typeof vmRuns === 'undefined' ? 0 : vmRuns) + 1;
$done({matched: vmRuns === 1 && $request.url.endsWith('/a') && $request.userAgent === 'Mobile'});`
	activateEvaluationScripts(t, directory, &ScriptsConfig{Enabled: true, Rule: []GenericScript{{Name: "choose", Source: source}}}, nil)
	request := RuleScriptRequest{Hostname: "api.example.test", DestPort: 443, SourcePort: 12000, Protocol: "HTTPS",
		SourceIP: "192.0.2.2", Resolved: true, DNSResult: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}}
	for _, sample := range []struct {
		path, agent string
		want        bool
	}{{"/a", "Mobile", true}, {"/b", "Mobile", false}, {"/a", "mobile", false}, {"/a", "Mobile", true}} {
		request.URL, request.UserAgent = "https://api.example.test"+sample.path, sample.agent
		matched, err := MatchRuleScript(context.Background(), "choose", request)
		if err != nil || matched != sample.want {
			t.Fatal("request condition was cached or metadata changed", sample, matched, err)
		}
	}
	if value := evaluationStoredCount(t, "rule-runs"); value != "4" {
		t.Fatal("script did not run separately for each request", value)
	}
	if matched, err := MatchRuleScript(WithoutScriptEvaluation(context.Background()), "choose", request); err != nil || matched {
		t.Fatal("recursive rule script ran", matched, err)
	}
	if value := evaluationStoredCount(t, "rule-runs"); value != "4" {
		t.Fatal("recursive evaluation changed storage", value)
	}
}

func TestRuleScriptsRejectInvalidResultsAndCancelIndependentVMs(t *testing.T) {
	directory := isolateScriptService(t)
	for _, source := range []string{`$done();`, `$done(true);`, `$done({matched:'true'});`, `$done({matched:1});`, `$done({policy:'direct'});`, `$done({matched:true,policy:'direct'});`} {
		activateEvaluationScripts(t, directory, &ScriptsConfig{Enabled: true, Rule: []GenericScript{{Name: "invalid", Source: source}}}, nil)
		if matched, err := MatchRuleScript(context.Background(), "invalid", RuleScriptRequest{}); err == nil || matched {
			t.Fatal("invalid script result selected a route", source, matched, err)
		}
	}
	activateEvaluationScripts(t, directory, &ScriptsConfig{Enabled: true, Rule: []GenericScript{{Name: "cancel", TimeoutMS: -1,
		Source: `if($request.url === 'hang') { for (;;) {} } $done({matched:true});`}}}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	if matched, err := MatchRuleScript(ctx, "cancel", RuleScriptRequest{URL: "hang"}); err == nil || matched {
		t.Fatal("cancelled script matched", matched, err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("rule VM ignored cancellation")
	}
	if matched, err := MatchRuleScript(context.Background(), "cancel", RuleScriptRequest{URL: "ready"}); err != nil || !matched {
		t.Fatal("cancelled VM affected the next request", matched, err)
	}
	if ruleScriptsRunning.Load() != 0 {
		t.Fatal("rule script runtime leaked")
	}
}

func TestRuleAndDNSScriptValidationIncludesDisabledEntries(t *testing.T) {
	for _, source := range []string{
		`{"rule":[{"source":"$done({matched:true});"}]}`,
		`{"dns":[{"name":"","source":"$done({});"}]}`,
		`{"rule":[{"name":"same","source":"$done({matched:true});"},{"name":"same","disabled":true,"source":"$done({matched:false});"}]}`,
		`{"dns":[{"name":"bad","disabled":true,"source":"function {"}]}`,
		`{"rule":[{"name":"bad","source":"$done({matched:true});","pattern":"."}]}`,
	} {
		var scripts ScriptsConfig
		if err := json.Unmarshal([]byte(source), &scripts); err == nil {
			t.Fatal("accepted invalid condition script", source)
		}
	}
}

func TestDNSScriptsPreserveHostOrderTTLCacheAndProfileIsolation(t *testing.T) {
	directory := isolateScriptService(t)
	config := &ScriptsConfig{Enabled: true, DNS: []GenericScript{{Name: "answer", Source: `if ($script.type !== 'dns' || $domain !== 'api.example.test' || typeof $request !== 'undefined') throw Error('context');
var n=Number($persistentStore.read('dns-runs')||0)+1; $persistentStore.write(String(n),'dns-runs');
$done({addresses:['192.0.2.10','2001:db8::10'],ttl:60});`}}}
	hosts := []DNSHost{{Pattern: "static.example.test", Addresses: []string{"192.0.2.20"}}, {Pattern: "*.example.test", Script: "answer"}}
	activateEvaluationScripts(t, directory, config, hosts)
	ctx := context.Background()
	first, matched, err := ResolveScriptDNS(ctx, "API.EXAMPLE.TEST.")
	if err != nil || !matched || first.Fallback || len(first.Addresses) != 2 || first.TTL != 60 {
		t.Fatal(first, matched, err)
	}
	first.Addresses[0] = netip.MustParseAddr("192.0.2.99")
	second, matched, err := ResolveScriptDNS(ctx, "api.example.test")
	if err != nil || !matched || second.Addresses[0].String() != "192.0.2.10" || second.TTL > 60 || evaluationStoredCount(t, "dns-runs") != "1" {
		t.Fatal("TTL cache was missed or aliased", second, err)
	}
	if _, _, err := ResolveScriptDNS(ctx, "api.example.test", true); err != nil || evaluationStoredCount(t, "dns-runs") != "2" {
		t.Fatal("disable_cache was ignored", err)
	}
	ClearScriptDNSCache()
	if _, _, err := ResolveScriptDNS(ctx, "api.example.test"); err != nil || evaluationStoredCount(t, "dns-runs") != "3" {
		t.Fatal("explicit cache clear was ignored", err)
	}
	static, matched, err := ResolveScriptDNS(WithoutScriptEvaluation(ctx), "static.example.test")
	if err != nil || !matched || len(static.Addresses) != 1 || static.Addresses[0].String() != "192.0.2.20" {
		t.Fatal("static Host mapping lost precedence or required scripts", static, err)
	}
	if _, matched, err := ResolveScriptDNS(WithoutScriptEvaluation(ctx), "api.example.test"); err != nil || matched {
		t.Fatal("DNS script recursively evaluated", matched, err)
	}
	if DNSHostMatched(ctx, "example.test") || !DNSHostMatched(ctx, "static.example.test") {
		t.Fatal("DNS glob widened an exact host")
	}
	config.DNS[0].Source = `$done({address:'192.0.2.30',ttl:60});`
	activateEvaluationScripts(t, directory, config, hosts)
	third, matched, err := ResolveScriptDNS(ctx, "api.example.test")
	if err != nil || !matched || third.Addresses[0].String() != "192.0.2.30" {
		t.Fatal("old profile DNS cache survived reload", third, err)
	}
}

func TestDNSScriptsRequireExplicitFallbackAndIPServerResults(t *testing.T) {
	directory := isolateScriptService(t)
	hosts := []DNSHost{{Pattern: "dns.test", Script: "answer"}}
	for _, source := range []string{`$done();`, `$done('192.0.2.1');`, `$done({address:'host.test'});`, `$done({server:'https://dns.test/dns-query'});`,
		`$done({server:'dns-tag'});`, `$done({server:'192.0.2.1:53'});`, `$done({server:'fe80::1%wlan0'});`,
		`$done({addresses:[]});`, `$done({addresses:['192.0.2.1'],address:'192.0.2.2'});`, `$done({address:'192.0.2.1',ttl:'60'});`,
		`$done({address:'192.0.2.1',ttl:-1});`, `$done({address:'192.0.2.1',ttl:1.5});`, `$done({address:'192.0.2.1',ttl:NaN});`,
		`$done({server:'192.0.2.1',ttl:10});`, `$done({addresses:['192.0.2.1'],unknown:true});`} {
		activateEvaluationScripts(t, directory, &ScriptsConfig{Enabled: true, DNS: []GenericScript{{Name: "answer", Source: source}}}, hosts)
		result, matched, err := ResolveScriptDNS(context.Background(), "dns.test")
		if err == nil || !matched || result.Fallback {
			t.Fatal("invalid DNS script silently fell back", source, result, matched, err)
		}
	}
	for _, source := range []string{`$done({});`, `$done({server:'192.0.2.53'});`, `$done({servers:['192.0.2.53','2001:db8::53']});`} {
		activateEvaluationScripts(t, directory, &ScriptsConfig{Enabled: true, DNS: []GenericScript{{Name: "answer", Source: source}}}, hosts)
		result, matched, err := ResolveScriptDNS(context.Background(), "dns.test")
		if err != nil || !matched || result.Fallback != strings.Contains(source, "({})") || result.TTLSet {
			t.Fatal("valid server or explicit fallback was lost", result, matched, err)
		}
	}
}

func TestStaticDNSHostsRemainActiveWithScriptsOff(t *testing.T) {
	directory := isolateScriptService(t)
	activateEvaluationScripts(t, directory, &ScriptsConfig{Enabled: false, DNS: []GenericScript{{Name: "off", Source: "$done({address:'192.0.2.99'});"}}},
		[]DNSHost{{Pattern: "static.test", Addresses: []string{"192.0.2.1"}}, {Pattern: "off.test", Script: "off"}})
	result, matched, err := ResolveScriptDNS(context.Background(), "static.test")
	if err != nil || !matched || result.Addresses[0].String() != "192.0.2.1" || Status().ScriptsActive {
		t.Fatal("static DNS was tied to the script switch", result, matched, err)
	}
	if _, matched, err := ResolveScriptDNS(context.Background(), "off.test"); err != nil || matched {
		t.Fatal("disabled DNS script executed", matched, err)
	}
}

func TestScriptEvaluationShutdownKeepsSelectedDNSHostHandled(t *testing.T) {
	directory := isolateScriptService(t)
	activateEvaluationScripts(t, directory, &ScriptsConfig{Enabled: true,
		Rule: []GenericScript{{Name: "condition", Source: `$done({matched:true});`}},
		DNS:  []GenericScript{{Name: "answer", Source: `$done({address:'192.0.2.1'});`}},
	}, []DNSHost{{Pattern: "dns.test", Script: "answer"}})
	// A caller may still hold the old engine after a reload closes its lifetime.
	// That race must never become an unmatched Host entry and normal DNS.
	Current().cancel()
	if matched, err := MatchRuleScript(context.Background(), "condition", RuleScriptRequest{}); matched || !errors.Is(err, context.Canceled) {
		t.Fatal("closed rule engine silently continued routing", matched, err)
	}
	if _, handled, err := ResolveScriptDNS(context.Background(), "dns.test"); !handled || !errors.Is(err, context.Canceled) {
		t.Fatal("closed DNS engine silently used normal DNS", handled, err)
	}
}

func TestDNSScriptAddressResultDecodingHonorsCancellation(t *testing.T) {
	for _, at := range []int{0, 1, 2} {
		ctx, cancel := context.WithCancel(context.Background())
		vm := goja.New()
		if err := vm.Set("cancelResult", func() { cancel() }); err != nil {
			t.Fatal(err)
		}
		if err := vm.Set("cancelAt", at); err != nil {
			t.Fatal(err)
		}
		value, err := vm.RunString(`var a=['192.0.2.1','192.0.2.2','192.0.2.3'];
Object.defineProperty(a,String(cancelAt),{get:function(){cancelResult();return '192.0.2.4';}});({addresses:a});`)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		_, err = decodeDNSScriptResult(ctx, value)
		cancel()
		if !errors.Is(err, context.Canceled) {
			t.Fatal("native DNS result callback ignored cancellation", at, err)
		}
	}
}
