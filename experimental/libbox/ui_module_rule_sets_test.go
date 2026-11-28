package libbox

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func uiSurgeRuleSetProfile(t *testing.T, profile moduleObject) string {
	t.Helper()
	data, err := json.Marshal(profile)
	require.NoError(t, err)
	return string(data)
}

func uiSurgeRuleSetOptions(t *testing.T, profile moduleObject) option.Options {
	t.Helper()
	content, err := effectiveModuleConfig(baseContext(nil), uiSurgeRuleSetProfile(t, profile))
	require.NoError(t, err)
	options, err := parseConfig(baseContext(nil), content)
	require.NoError(t, err)
	return options
}

func TestUISurgeExternalRuleSetsAreExplicitAndDoNotDownloadWhileChecking(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("DOMAIN,downloaded.test"))
	}))
	defer server.Close()
	module := option.ModuleOptions{ID: "remote", Enabled: true, URL: server.URL + "/modules/example.sgmodule", Content: "[Rule]\nRULE-SET,../rules.list,DIRECT,update-interval=60\nDOMAIN-SET,../domains.list,DIRECT,update-interval=-1"}
	profile := moduleObject{"experimental": moduleObject{"modules": []option.ModuleOptions{module}}}
	require.NoError(t, CheckConfig(uiSurgeRuleSetProfile(t, profile)))
	options := uiSurgeRuleSetOptions(t, profile)
	require.Equal(t, int32(0), requests.Load(), "CheckConfig fetched an external rule-set")
	require.Len(t, options.Route.RuleSet, 2)
	rules, domains := options.Route.RuleSet[0], options.Route.RuleSet[1]
	require.Equal(t, C.RuleSetFormatSurgeRules, rules.Format)
	require.Equal(t, server.URL+"/rules.list", rules.RemoteOptions.URL)
	require.Equal(t, time.Minute, time.Duration(rules.RemoteOptions.UpdateInterval))
	require.Equal(t, "remote/", rules.RemoteOptions.ScriptNamespace)
	require.Equal(t, C.RuleSetFormatSurgeDomains, domains.Format)
	require.Equal(t, server.URL+"/domains.list", domains.RemoteOptions.URL)
	require.Equal(t, -time.Second, time.Duration(domains.RemoteOptions.UpdateInterval))
	require.Empty(t, domains.RemoteOptions.ScriptNamespace)
	require.Equal(t, rules.Tag[0], options.Route.Rules[0].DefaultOptions.RuleSet[0])
	require.Equal(t, domains.Tag[0], options.Route.Rules[1].DefaultOptions.RuleSet[0])
}

func TestUISurgeInlineRuleSetsResolveLaterDeclarationsAndScopedScripts(t *testing.T) {
	module := option.ModuleOptions{ID: "inline", Enabled: true, Content: `[Rule]
RULE-SET,later,DIRECT,no-resolve,extended-matching
RULE-SET,existing,DIRECT
[Ruleset later]
DOMAIN,first.test,extended-matching
DOMAIN,second.test
AND,((URL-REGEX,/secret),(SCRIPT,choose))
[Script]
choose=type=rule,script-path=choose.js`, Attachments: map[string]string{"choose.js": base64.StdEncoding.EncodeToString([]byte("$done({matched:true});"))}}
	profile := moduleObject{"route": moduleObject{"rule_set": []moduleObject{{"type": "inline", "tag": "existing", "rules": []moduleObject{{"domain": "base.test"}}}}}, "experimental": moduleObject{"modules": []option.ModuleOptions{module}}}
	require.NoError(t, CheckConfig(uiSurgeRuleSetProfile(t, profile)))
	options := uiSurgeRuleSetOptions(t, profile)
	require.Len(t, options.Route.RuleSet, 2)
	require.Len(t, options.Route.Rules, 2)
	outer := options.Route.Rules[0].DefaultOptions
	require.True(t, outer.SurgeNoResolve)
	require.True(t, outer.HTTPExtendedMatching)
	inline := options.Route.RuleSet[1]
	require.Equal(t, inline.Tag[0], outer.RuleSet[0])
	require.Equal(t, "existing", options.Route.Rules[1].DefaultOptions.RuleSet[0])
	require.Len(t, inline.InlineOptions.Rules, 3)
	require.True(t, inline.InlineOptions.Rules[0].DefaultOptions.HTTPExtendedMatching)
	require.True(t, inline.InlineOptions.Rules[1].DefaultOptions.HTTPExtendedMatching)
	require.Equal(t, "inline/choose", inline.InlineOptions.Rules[2].LogicalOptions.Rules[1].DefaultOptions.Script)
	require.Equal(t, "inline/choose", options.Experimental.Scripts.Rule[0].Name)
	module.Enabled = false
	profile["experimental"] = moduleObject{"modules": []option.ModuleOptions{module}}
	options = uiSurgeRuleSetOptions(t, profile)
	require.Len(t, options.Route.RuleSet, 1)
	require.Empty(t, options.Route.Rules)
	require.Equal(t, "existing", options.Route.RuleSet[0].Tag[0])
}

func TestUISurgeRuleSetAttachmentsKeepTheirDeclaredTextFormat(t *testing.T) {
	module := option.ModuleOptions{ID: "files", Enabled: true, Content: "[Rule]\nRULE-SET,rules.list,DIRECT\nDOMAIN-SET,domains.list,DIRECT", Attachments: map[string]string{
		"rules.list":   base64.StdEncoding.EncodeToString([]byte("DOMAIN,exact.test\nUSER-AGENT,App?/*")),
		"domains.list": base64.StdEncoding.EncodeToString([]byte("# domains\nexact.test\n.suffix.test")),
	}}
	profile := moduleObject{"experimental": moduleObject{"modules": []option.ModuleOptions{module}}}
	require.NoError(t, CheckConfig(uiSurgeRuleSetProfile(t, profile)))
	options := uiSurgeRuleSetOptions(t, profile)
	require.Len(t, options.Route.RuleSet, 2)
	require.Equal(t, "App?/*", options.Route.RuleSet[0].InlineOptions.Rules[1].DefaultOptions.HTTPUserAgent[0])
	require.Equal(t, "exact.test", options.Route.RuleSet[1].InlineOptions.Rules[0].DefaultOptions.Domain[0])
	require.Equal(t, "suffix.test", options.Route.RuleSet[1].InlineOptions.Rules[1].DefaultOptions.DomainSuffix[0])
	module.Attachments["rules.list"] = base64.StdEncoding.EncodeToString([]byte(`{"version":3,"rules":[{"domain":"json.test"}]}`))
	profile["experimental"] = moduleObject{"modules": []option.ModuleOptions{module}}
	_, err := effectiveModuleConfig(baseContext(nil), uiSurgeRuleSetProfile(t, profile))
	require.ErrorContains(t, err, "no supported rules")
}

func TestUISurgeURLRegexParenthesesAndQuotedCommasSurviveRulesAndRuleSets(t *testing.T) {
	module := option.ModuleOptions{ID: "regex", Enabled: true, Content: `[Rule]
URL-REGEX,^https://x/[(]foo,DIRECT
URL-REGEX,^https://x/[^)]*,DIRECT
URL-REGEX,^https://x/\(foo,DIRECT
URL-REGEX,"^https://x/(a|b),?c",DIRECT
RULE-SET,later,DIRECT
RULE-SET,rules.list,DIRECT
[Ruleset later]
URL-REGEX,^https://x/[(]foo
URL-REGEX,^https://x/[^)]*
URL-REGEX,^https://x/\(foo
URL-REGEX,"^https://x/(a|b),?c"`, Attachments: map[string]string{"rules.list": base64.StdEncoding.EncodeToString([]byte(`URL-REGEX,^https://x/[(]foo
URL-REGEX,^https://x/[^)]*
URL-REGEX,^https://x/\(foo
URL-REGEX,"^https://x/(a|b),?c"`))}}
	parsed := readModule(module)
	require.Empty(t, parsed.Lines["ignored"], "valid regex parentheses were treated as logical grouping")
	profile := moduleObject{"experimental": moduleObject{"modules": []option.ModuleOptions{module}}}
	require.NoError(t, CheckConfig(uiSurgeRuleSetProfile(t, profile)))
	options := uiSurgeRuleSetOptions(t, profile)
	require.Len(t, options.Route.Rules, 6)
	require.Len(t, options.Route.RuleSet, 2)
	patterns := []string{`^https://x/[(]foo`, `^https://x/[^)]*`, `^https://x/\(foo`, `^https://x/(a|b),?c`}
	for index, pattern := range patterns {
		require.Equal(t, []string{pattern}, []string(options.Route.Rules[index].DefaultOptions.HTTPURLRegex))
	}
	for _, set := range options.Route.RuleSet {
		require.Len(t, set.InlineOptions.Rules, len(patterns))
		for index, pattern := range patterns {
			require.Equal(t, []string{pattern}, []string(set.InlineOptions.Rules[index].DefaultOptions.HTTPURLRegex))
		}
	}
}

func TestUISurgeRuleSetsRejectResourceAndNestedSetAmbiguity(t *testing.T) {
	for _, sample := range []struct{ content, want string }{
		{"[Rule]\nRULE-SET,https://example.test/shared,DIRECT\nDOMAIN-SET,https://example.test/shared,DIRECT", "both RULE-SET and DOMAIN-SET"},
		{"[Rule]\nRULE-SET,https://example.test/shared,DIRECT\nRULE-SET,https://example.test/shared,DIRECT,update-interval=60", "conflicting update intervals"},
		{"[Rule]\nRULE-SET,later,DIRECT\n[Ruleset later]\nDOMAIN,valid.test\nRULE-SET,nested.list", "nested RULE-SET"},
		{"[Rule]\nRULE-SET,later,DIRECT\n[Ruleset later]\nDOMAIN,first.test\n[Ruleset later]\nDOMAIN,second.test", "duplicate inline rule-set"},
		{"[Rule]\nRULE-SET,later,DIRECT,update-interval=60\n[Ruleset later]\nDOMAIN,first.test", "cannot apply to an inline"},
	} {
		module := option.ModuleOptions{ID: "invalid", Enabled: true, Content: sample.content}
		profile := moduleObject{"experimental": moduleObject{"modules": []option.ModuleOptions{module}}}
		_, err := effectiveModuleConfig(baseContext(nil), uiSurgeRuleSetProfile(t, profile))
		require.ErrorContains(t, err, sample.want, sample.content)
	}
	module := option.ModuleOptions{ID: "skip", Enabled: true, Content: "[Rule]\nRULE-SET,later,DIRECT\n[Ruleset later]\nOR,((DOMAIN,unsafe.test),(UNSUPPORTED,value))\nDOMAIN,safe.test"}
	options := uiSurgeRuleSetOptions(t, moduleObject{"experimental": moduleObject{"modules": []option.ModuleOptions{module}}})
	require.Len(t, options.Route.RuleSet[0].InlineOptions.Rules, 1)
	require.Equal(t, "safe.test", options.Route.RuleSet[0].InlineOptions.Rules[0].DefaultOptions.Domain[0])
	module.Content = "[Rule]\nRULE-SET,https://example.test/shared,DIRECT\nRULE-SET,https://example.test/shared,DIRECT,update-interval=86400"
	options = uiSurgeRuleSetOptions(t, moduleObject{"experimental": moduleObject{"modules": []option.ModuleOptions{module}}})
	require.Len(t, options.Route.RuleSet, 1, "equivalent default intervals duplicated one module resource")
}

func TestUISurgeForceHTTPEngineHostsPreserveOrderedPatchesAndDisable(t *testing.T) {
	for _, sample := range []struct {
		content string
		want    []string
		invalid bool
	}{
		{"force-http-engine-hosts=%APPEND% last.test\nforce-http-engine-hosts=%INSERT% -private.test,*.example.test:0", []string{"-private.test", "*.example.test:0", "base.test", "last.test"}, false},
		{"force-http-engine-hosts=%APPEND% discarded.test\nforce-http-engine-hosts=replaced.test\nforce-http-engine-hosts=%INSERT% first.test", []string{"first.test", "replaced.test"}, false},
		{"force-http-engine-hosts=", []string{}, false},
		{"force-http-engine-hosts=%APPEND% broken.test/path,good.test", []string{"base.test", "good.test"}, false},
		{"force-http-engine-hosts=%APPEND% *, -private.test/path", nil, true},
		{"force-http-engine-hosts=broken.test/path", nil, true},
	} {
		module := option.ModuleOptions{ID: "force", Enabled: true, Content: "[General]\n" + sample.content}
		profile := moduleObject{"experimental": moduleObject{"http_routing": moduleObject{"enabled": false, "force_http_engine_hosts": []string{"base.test"}}, "modules": []option.ModuleOptions{module}}}
		content, err := effectiveModuleConfig(baseContext(nil), uiSurgeRuleSetProfile(t, profile))
		if sample.invalid {
			require.Error(t, err)
			continue
		}
		require.NoError(t, err)
		options, err := parseConfig(baseContext(nil), content)
		require.NoError(t, err)
		require.Equal(t, sample.want, []string(options.Experimental.HTTPRouting.ForceHTTPEngineHosts))
		require.True(t, options.Experimental.HTTPRouting.Enabled)
		module.Enabled = false
		profile["experimental"] = moduleObject{"http_routing": moduleObject{"enabled": false, "force_http_engine_hosts": []string{"base.test"}}, "modules": []option.ModuleOptions{module}}
		options = uiSurgeRuleSetOptions(t, profile)
		require.False(t, options.Experimental.HTTPRouting.Enabled)
		require.Equal(t, []string{"base.test"}, []string(options.Experimental.HTTPRouting.ForceHTTPEngineHosts))
	}
}
