package libbox

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

// This is a complete native profile, independent of the app repository's
// examples and module conversion. Remote bytes are deliberately unavailable
// during validation, including the named rule/DNS script sources.
func uiHTTPRoutingConfigFixture(remote string) string {
	return fmt.Sprintf(`{
  "dns":{"servers":[{"type":"udp","tag":"dns","server":"192.0.2.53"}],"rules":[{"rule_set":"inline-requests","server":"dns"}],"final":"dns"},
  "outbounds":[{"type":"direct","tag":"direct"},{"type":"direct","tag":"proxy"}],
  "route":{
    "rules":[
      {"http_url_regex":"^https://api\\.test/private/","outbound":"proxy"},
      {"http_user_agent":"Mobile*","outbound":"proxy"},
      {"script":"choose","script_requires_resolve":true,"outbound":"proxy"},
      {"rule_set":"inline-requests","http_extended_matching":true,"outbound":"direct"},
      {"rule_set":"remote-requests","surge_no_resolve":true,"outbound":"proxy"},
      {"rule_set":"remote-domains","outbound":"direct"},
      {"http_url_regex":"/blocked$","action":"reject","http_response":"reject-dict"}
    ],
    "rule_set":[
      {"type":"inline","tag":"inline-requests","rules":[
        {"http_url_regex":"/public$"},{"http_user_agent":"Desktop*"},
        {"script":"choose","script_requires_resolve":true},
        {"surge_protocol":"HTTPS"},{"domain":"api.test","http_extended_matching":true},
        {"ip_cidr":"198.51.100.0/24","surge_ip_cidr":true,"surge_no_resolve":true}
      ]},
      {"type":"remote","tag":"remote-requests","format":"surge-rule-set","url":%q,"http_client":{"detour":"proxy"},"update_interval":"86400s"},
      {"type":"remote","tag":"remote-domains","format":"surge-domain-set","url":%q,"update_interval":"-1s"}
    ],
    "final":"direct"
  },
  "experimental":{
    "http_routing":{"enabled":true,"force_http_engine_hosts":["-internal.test:8080","api?.test:8080","*.test:0","<simple-hostname>:8080","<ip-address>:8080"]},
    "mitm":{"enabled":true,"hosts":["api.test"],"h2":true},
    "scripts":{"enabled":true,
      "rule":[{"name":"choose","source":"throw new Error('validation executed rule script');"},{"name":"remote-condition","script_path":%q,"script_update_interval":-1}],
      "dns":[{"name":"answer","source":"throw new Error('validation executed DNS script');"},{"name":"remote-answer","script_path":%q}]
    },
    "dns_hosts":[{"pattern":"static.test","addresses":["192.0.2.20","2001:db8::20"]},{"pattern":"*.test","script":"answer"}]
  }
}`, remote+"/requests.list", remote+"/domains.list", remote+"/condition.js", remote+"/answer.js")
}

func TestUIHTTPRoutingCompleteConfigValidationAndFormatDoNotDownloadResources(t *testing.T) {
	var downloads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		downloads.Add(1)
		http.Error(writer, "validation must not download "+request.URL.Path, http.StatusServiceUnavailable)
	}))
	defer server.Close()
	content := uiHTTPRoutingConfigFixture(server.URL)
	require.NoError(t, CheckConfig(content))
	needsCA, err := NeedsUIMITMCA(content)
	require.NoError(t, err)
	require.True(t, needsCA)
	original, err := parseConfig(baseContext(nil), content)
	require.NoError(t, err)
	formatted, err := FormatConfig(content)
	require.NoError(t, err)
	require.NoError(t, CheckConfig(formatted.Value))
	actual, err := parseConfig(baseContext(nil), formatted.Value)
	require.NoError(t, err)
	require.Equal(t, original.Route.Rules, actual.Route.Rules, "format changed ordered request conditions or actions")
	require.Equal(t, original.Route.RuleSet, actual.Route.RuleSet, "format changed inline rules or remote format/update policy")
	require.Equal(t, original.DNS.Rules, actual.DNS.Rules)
	require.Equal(t, original.Experimental.HTTPRouting, actual.Experimental.HTTPRouting)
	require.Equal(t, original.Experimental.MITM, actual.Experimental.MITM)
	require.Equal(t, original.Experimental.Scripts, actual.Experimental.Scripts)
	require.Equal(t, original.Experimental.DNSHosts, actual.Experimental.DNSHosts, "format changed ordered Host mappings")
	require.Equal(t, C.RuleSetTypeInline, actual.Route.RuleSet[0].Type)
	require.Len(t, actual.Route.RuleSet[0].InlineOptions.Rules, 6)
	require.Equal(t, C.RuleSetFormatSurgeRules, actual.Route.RuleSet[1].Format)
	require.Equal(t, C.RuleSetFormatSurgeDomains, actual.Route.RuleSet[2].Format)
	for _, field := range []string{`"format": "surge-rule-set"`, `"format": "surge-domain-set"`, `"http_response": "reject-dict"`, `"script_update_interval": -1`} {
		require.Contains(t, formatted.Value, field)
	}
	require.Zero(t, downloads.Load(), "complete config validation or formatting performed a remote fetch")
}

func TestUIHTTPRoutingCompleteConfigRejectsInvalidReferencesSourcesAndActions(t *testing.T) {
	content := uiHTTPRoutingConfigFixture("https://unfetched.invalid")
	for _, test := range []struct {
		name, old, replacement, reason string
	}{
		{"unknown route script", `"script":"choose","script_requires_resolve":true,"outbound":"proxy"`, `"script":"missing","script_requires_resolve":true,"outbound":"proxy"`, "not configured"},
		{"unknown inline script", `{"script":"choose","script_requires_resolve":true}`, `{"script":"missing","script_requires_resolve":true}`, "not configured"},
		{"unknown DNS script", `"script":"answer"`, `"script":"missing"`, "not configured"},
		{"resolve without script", `"script":"choose","script_requires_resolve":true,"outbound":"proxy"`, `"script_requires_resolve":true,"outbound":"proxy"`, "requires a script condition"},
		{"conflicting rule source", `"name":"choose","source":`, `"name":"choose","script_path":"https://unfetched.invalid/choose.js","source":`, "choose exactly one"},
		{"conflicting DNS source", `"name":"answer","source":`, `"name":"answer","script_path":"https://unfetched.invalid/answer.js","source":`, "choose exactly one"},
		{"conflicting Host action", `"pattern":"*.test","script":"answer"`, `"pattern":"*.test","script":"answer","addresses":["192.0.2.1"]`, "exactly one"},
		{"reject with route action", `"action":"reject","http_response":"reject-dict"`, `"action":"route","http_response":"reject-dict","outbound":"direct"`, "http_response"},
		{"drop with HTTP response", `"action":"reject","http_response":"reject-dict"`, `"action":"reject","method":"drop","http_response":"reject-dict"`, "drop method"},
		{"DNS cannot return HTTP response", `"rule_set":"inline-requests","server":"dns"`, `"rule_set":"inline-requests","action":"reject","http_response":"reject-dict"`, "not DNS rule actions"},
		{"nested inline reference", `{"http_url_regex":"/public$"}`, `{"rule_set":"remote-requests"}`, "rule_set"},
		{"bad forced host", `"<ip-address>:8080"`, `"api.test:70000"`, "force HTTP engine host"},
		{"implicit Surge text format", `"format":"surge-rule-set",`, ``, "missing format"},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Contains(t, content, test.old)
			invalid := strings.Replace(content, test.old, test.replacement, 1)
			err := CheckConfig(invalid)
			require.ErrorContains(t, err, test.reason)
		})
	}
}

func TestUIHTTPRoutingConfigSchemaIncludesNativeExtensions(t *testing.T) {
	result, err := GenerateConfigSchema()
	require.NoError(t, err)
	var document map[string]any
	require.NoError(t, json.Unmarshal([]byte(result.Value), &document))
	// Look for actual schema properties, rather than incidental prose or enum
	// strings; definitions can contain unions and references between variants.
	properties := make(map[string][]map[string]any)
	var visit func(any)
	visit = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			if fields, ok := value["properties"].(map[string]any); ok {
				for name, property := range fields {
					if node, ok := property.(map[string]any); ok {
						properties[name] = append(properties[name], node)
					}
				}
			}
			for _, child := range value {
				visit(child)
			}
		case []any:
			for _, child := range value {
				visit(child)
			}
		}
	}
	visit(document)
	for _, name := range []string{"http_routing", "force_http_engine_hosts", "http_url_regex", "http_user_agent", "http_extended_matching", "surge_protocol", "surge_ip_cidr", "surge_no_resolve", "script", "script_requires_resolve", "scripts", "rule", "dns", "dns_hosts", "pattern", "addresses", "http_response", "script_namespace"} {
		require.NotEmpty(t, properties[name], "missing native schema property %s", name)
	}
	require.Equal(t, "array", properties["force_http_engine_hosts"][0]["type"])
	require.Equal(t, "array", properties["dns_hosts"][0]["type"])
	for _, format := range []string{C.RuleSetFormatSurgeRules, C.RuleSetFormatSurgeDomains} {
		found := false
		for _, property := range properties["format"] {
			values, _ := property["enum"].([]any)
			for _, value := range values {
				found = found || value == format
			}
		}
		require.True(t, found, "explicit rule-set format %s missing from schema enum", format)
	}
}
