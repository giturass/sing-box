package libbox

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestUIModulePanels(t *testing.T) {
	const declaration = `[Panel]
Static = title="Title, text",content="One\nTwo",style=info
Dynamic = script-name=helper, update-interval=60
Missing = script-name=absent
Dynamic = title=Duplicate
Invalid = title=X, style=unsupported
[Script]
helper = script-path=helper.js`
	module := option.ModuleOptions{ID: "panels", Enabled: true, Content: declaration, Attachments: map[string]string{"helper.js": "JGRvbmUoKTs="}}
	parsed := readModule(module)
	if len(parsed.Panels) != 2 || len(parsed.Lines["ignored"]) != 3 || parsed.Panels[0].Index != -1 || parsed.Panels[0].Title != "Title, text" || parsed.Panels[0].Content != "One\nTwo" || parsed.Panels[0].Style != "info" || parsed.Panels[1].UpdateInterval != 60 {
		t.Fatal(parsed)
	}
	prior := module
	prior.ID, prior.Content = "earlier", "[Script]\nother = script-path=helper.js"
	disabled := prior
	disabled.ID, disabled.Enabled = "off", false
	data, err := json.Marshal(moduleObject{"experimental": moduleObject{"scripts": moduleObject{"generic": []moduleObject{{"name": "base", "source": "$done()"}}}, "modules": []option.ModuleOptions{prior, disabled, module}}})
	if err != nil {
		t.Fatal(err)
	}
	list, err := DescribeProfileSurgePanels(string(data))
	var panels []modulePanel
	if err != nil || json.Unmarshal([]byte(list), &panels) != nil || len(panels) != 2 || panels[0].Index != -1 || panels[1].Index != 2 || panels[1].ModuleID != "panels" {
		t.Fatal(list, err)
	}
	details, err := DescribeProfileSurgeModule(string(data), "panels")
	if err != nil || json.Unmarshal([]byte(details), &parsed) != nil || parsed.Panels[1].Index != 2 {
		t.Fatal(details, err)
	}
}

func TestUIModuleHostScope(t *testing.T) {
	for _, sample := range []struct {
		lines, want, shown string
		ignored            int
		invalid            bool
	}{
		{"hostname = %APPEND% static.test/path, good.test", "base.test,good.test", "good.test", 1, false},
		{"hostname = %APPEND% static.test/path", "base.test", "", 1, false},
		{"hostname = %APPEND% last.test\nhostname = %INSERT% first.test", "first.test,base.test,last.test", "first.test last.test", 0, false},
		{"hostname = %APPEND% discarded.test\nhostname = replaced.test\nhostname = %INSERT% first.test", "first.test,replaced.test", "first.test replaced.test", 0, false},
		{"hostname = %APPEND% -private.test, , *.example.test, [2001:db8::1]:8443,", "base.test,-private.test,*.example.test,[2001:db8::1]:8443", "-private.test *.example.test [2001:db8::1]:8443", 0, false},
		{"hostname =", "", "", 0, false},
		{"hostname = %APPEND% *, -secret.test/path", "", "", 1, true},
		{"hostname = broken.test/path", "", "", 1, true},
	} {
		module := option.ModuleOptions{ID: "scope", Enabled: true, Content: "[MITM]\n" + sample.lines}
		data, err := json.Marshal(moduleObject{"experimental": moduleObject{"mitm": moduleObject{"hosts": []string{"base.test"}}, "modules": []option.ModuleOptions{module}}})
		if err != nil {
			t.Fatal(err)
		}
		details, err := DescribeProfileSurgeModule(string(data), module.ID)
		if err != nil {
			t.Fatal(err)
		}
		var parsed moduleDescription
		if err := json.Unmarshal([]byte(details), &parsed); err != nil {
			t.Fatal(err)
		}
		var shown []string
		for _, line := range parsed.Lines["mitm"] {
			shown = append(shown, line.Text)
		}
		if !slices.Equal(shown, strings.Fields(sample.shown)) || len(parsed.Lines["ignored"]) != sample.ignored {
			t.Fatalf("%s: unexpected details: %s", sample.lines, details)
		}
		result, err := effectiveModuleConfig(baseContext(nil), string(data))
		if sample.invalid {
			if err == nil {
				t.Fatal("malformed scope admitted:", sample.lines)
			}
			continue
		}
		if err != nil {
			t.Fatal(sample.lines, err)
		}
		options, err := parseConfig(baseContext(nil), result)
		if err != nil || strings.Join(options.Experimental.MITM.Hosts, ",") != sample.want {
			t.Fatal(sample.lines, result, err)
		}
	}
}

func TestUISurgeModuleLifecycle(t *testing.T) {
	module := option.ModuleOptions{ID: "one", Enabled: true, Content: "#!name=Example\n#!arguments=site:default.test\n[Rule]\nDOMAIN,{{{site}}},DIRECT\nAND,((DOMAIN-SUFFIX,example.test),(DEST-PORT,80-90)),REJECT-DROP\n[MITM]\nhostname = %INSERT% first.test\n[URL Rewrite]\n^https://example.test/ - reject\n[Script]\nhelper = type=generic,script-path=helper.js", Arguments: map[string]string{"site": "one.test"}, Attachments: map[string]string{"helper.js": "JGRvbmUoKTs="}}
	profile := func() string {
		data, err := json.Marshal(moduleObject{"outbounds": []any{moduleObject{"type": "direct", "tag": "module-direct"}}, "experimental": moduleObject{"modules": []any{module}, "scripts": moduleObject{"generic": []any{moduleObject{"name": "base", "source": "$done();"}}}, "mitm": moduleObject{"hosts": []string{"base.test"}}}})
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	content := profile()
	if err := CheckConfig(content); err != nil {
		t.Fatal(err)
	}
	formatted, err := FormatConfig(content)
	if err != nil || strings.Contains(formatted.Value, `"domain":`) || !strings.Contains(formatted.Value, `"modules"`) {
		t.Fatal(formatted, err)
	}
	expanded, err := effectiveModuleConfig(baseContext(nil), formatted.Value)
	if err != nil {
		t.Fatal(err)
	}
	options, err := parseConfig(baseContext(nil), expanded)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Route.Rules) != 2 || len(options.Outbounds) != 2 || options.Outbounds[1].Tag != "module-direct-2" || options.Route.Rules[0].DefaultOptions.Domain[0] != "one.test" {
		t.Fatal(expanded)
	}
	scripts := options.Experimental.Scripts
	if scripts.Enabled || len(scripts.Generic) != 2 || scripts.Generic[0].Name != "base" || scripts.Generic[1].Source != "$done();" || options.Experimental.HTTPRewrite.Enabled || len(options.Experimental.HTTPRewrite.URLRewrite) != 1 || options.Experimental.MITM.Hosts[0] != "first.test" {
		t.Fatal(expanded)
	}
	again, err := effectiveModuleConfig(baseContext(nil), expanded)
	if err != nil || again != expanded {
		t.Fatal("expanded twice", err)
	}
	module.Enabled = false
	expanded, err = effectiveModuleConfig(baseContext(nil), profile())
	if err != nil || strings.Contains(expanded, `"route"`) || strings.Contains(expanded, "module-direct-2") {
		t.Fatal(expanded, err)
	}
}

func TestUISurgeModuleCommentedProfile(t *testing.T) {
	const pattern = `^https://example.test/path//asset`
	content := `// b-box-local-nodes: ["Local"]
{
  /* base settings */
  "outbounds": [` + uiNodeTestNode("Local", "192.0.2.1") + `],
  "experimental": {
    "http_rewrite": {"max_body_bytes": 9007199254740993},
    "modules": [
      {"id":"on","enabled":true,"content":"[URL Rewrite]\n` + pattern + ` - reject"},
      {"id":"off","enabled":false,"content":"[URL Rewrite]\n^https://disabled.test/ - reject"}
    ]
  }
}`
	if err := CheckConfig(content); err != nil {
		t.Fatal(err)
	}
	formatted, err := FormatConfig(content)
	if err != nil {
		t.Fatal(err)
	}
	uiNodeTestLocal(t, formatted.Value, "Local")
	if !strings.Contains(formatted.Value, `"modules"`) || !strings.Contains(formatted.Value, pattern+` - reject`) || strings.Contains(formatted.Value, `"url_rewrite"`) {
		t.Fatalf("formatted profile changed module storage: %s", formatted.Value)
	}
	ctx := baseContext(nil)
	expanded, err := effectiveModuleConfig(ctx, formatted.Value)
	if err != nil {
		t.Fatal(err)
	}
	options, err := parseConfig(ctx, expanded)
	if err != nil {
		t.Fatal(err)
	}
	rewrite := options.Experimental.HTTPRewrite
	if rewrite.MaxBodyBytes != 9007199254740993 || len(rewrite.URLRewrite) != 1 || rewrite.URLRewrite[0].Pattern != pattern {
		t.Fatalf("incorrect effective settings: %s", expanded)
	}
	if err := CheckConfig(strings.Replace(content, "/* base settings */", "/", 1)); err == nil {
		t.Fatal("accepted a bare slash outside a string")
	}
}

func TestUISurgeModuleDiagnosticsAndSources(t *testing.T) {
	source := option.ModuleOptions{URL: "https://example.test/modules/one.sgmodule", Content: "[Rule]\nOR,((DOMAIN,ok.test),(UNSUPPORTED,other)),REJECT\nIP-CIDR,192.0.2.0/24,REJECT,no-resolve\n[Script]\njob = type=generic,script-path=job.js\nother = type=generic,script-path=file:///private.js\n[Host]\na.test = 192.0.2.1"}
	parsed := readModule(source)
	if len(parsed.Lines["ignored"]) != 2 || len(parsed.values["rules"]) != 1 || !parsed.HasScripts || parsed.values["generic"][0].(moduleObject)["script_path"] != "https://example.test/modules/job.js" || len(parsed.values["dns_host"]) == 0 {
		t.Fatal(parsed)
	}
	source.URL = ""
	if parsed = readModule(source); len(parsed.values["generic"]) != 0 {
		t.Fatal("local module read arbitrary profile file")
	}
}

func TestUISurgeModuleHTTPAndRoutePolicies(t *testing.T) {
	parsed := readModule(option.ModuleOptions{Content: "[Rule]\nURL-REGEX,^https://example.test/,REJECT-DICT\nURL-REGEX,other,DIRECT\nUSER-AGENT,Browser/*,proxy\nNETWORK-TYPE,wifi,REJECT-NO-DROP\nRULE-SET,https://example.test/rules,REJECT\nRULE-SET,local-rules,REJECT\nDOMAIN,example.test,\"\""})
	if len(parsed.values["url_rewrite"]) != 0 || len(parsed.values["rules"]) != 6 || len(parsed.Lines["ignored"]) != 1 || parsed.values["rules"][0].(moduleObject)["http_response"] != "reject-dict" || parsed.values["rules"][2].(moduleObject)["http_user_agent"] != "Browser/*" || parsed.values["rules"][3].(moduleObject)["no_drop"] != true {
		t.Fatal(parsed)
	}
}

func TestUISurgeModuleParameterCommentDoesNotActivateScript(t *testing.T) {
	source := option.ModuleOptions{Content: "#!arguments=prefix://\n[Script]\n{{{prefix}}}helper=type=generic,script-path=helper.js", Attachments: map[string]string{"helper.js": "JGRvbmUoKTs="}}
	if parsed := readModule(source); !parsed.HasScripts || len(parsed.values["generic"]) != 0 {
		t.Fatal(parsed)
	}
	source.Arguments = map[string]string{"prefix": ""}
	if parsed := readModule(source); len(parsed.values["generic"]) != 1 {
		t.Fatal(parsed)
	}
}
