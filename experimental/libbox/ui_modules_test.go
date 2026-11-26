package libbox

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

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

func TestUISurgeModuleDiagnosticsAndSources(t *testing.T) {
	source := option.ModuleOptions{URL: "https://example.test/modules/one.sgmodule", Content: "[Rule]\nOR,((DOMAIN,ok.test),(UNSUPPORTED,other)),REJECT\nIP-CIDR,192.0.2.0/24,REJECT,no-resolve\n[Script]\njob = type=generic,script-path=job.js\nother = type=generic,script-path=file:///private.js\n[Host]\na.test = 192.0.2.1"}
	parsed := readModule(source)
	if len(parsed.Lines["ignored"]) != 2 || len(parsed.values["rules"]) != 1 || !parsed.HasScripts || parsed.values["generic"][0].(moduleObject)["script_path"] != "https://example.test/modules/job.js" || len(parsed.values["dns"]) == 0 {
		t.Fatal(parsed)
	}
	source.URL = ""
	if parsed = readModule(source); len(parsed.values["generic"]) != 0 {
		t.Fatal("local module read arbitrary profile file")
	}
}

func TestUISurgeModuleHTTPAndRoutePolicies(t *testing.T) {
	parsed := readModule(option.ModuleOptions{Content: "[Rule]\nURL-REGEX,^https://example.test/,REJECT-DICT\nURL-REGEX,other,DIRECT\nNETWORK-TYPE,wifi,REJECT-NO-DROP\nRULE-SET,https://example.test/rules,REJECT\nRULE-SET,local-rules,REJECT\nDOMAIN,example.test,\"\""})
	if len(parsed.values["url_rewrite"]) != 1 || len(parsed.values["rules"]) != 2 || len(parsed.Lines["ignored"]) != 3 || parsed.values["rules"][0].(moduleObject)["no_drop"] != true {
		t.Fatal(parsed)
	}
}
