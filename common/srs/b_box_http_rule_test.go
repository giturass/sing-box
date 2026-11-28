package srs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestBBoxRuleSetExportRejectsUnrepresentableSourceConditions(t *testing.T) {
	t.Parallel()
	conditions := []struct {
		name string
		json string
	}{
		{"url", `"http_url_regex":["/private/"]`},
		{"user_agent", `"http_user_agent":["Mobile*"]`},
		{"extended_matching", `"http_extended_matching":true`},
		{"script", `"script":"route-check"`},
		{"requires_resolve", `"script_requires_resolve":true`},
		{"surge_ip", `"surge_ip_cidr":true`},
		{"no_resolve", `"surge_no_resolve":true`},
		{"surge_protocol", `"surge_protocol":["HTTPS"]`},
		{"native_protocol", `"protocol":["http"]`},
	}
	for _, condition := range conditions {
		t.Run(condition.name, func(t *testing.T) {
			t.Parallel()
			leaf := fmt.Sprintf(`{"domain_keyword":["example"],"ip_cidr":["192.0.2.0/24"],%s}`, condition.json)
			for _, mode := range []string{"default", "and", "or"} {
				t.Run(mode, func(t *testing.T) {
					rule := leaf
					if mode != "default" {
						rule = fmt.Sprintf(`{"type":"logical","mode":%q,"invert":true,"rules":[{"domain_keyword":["safe"]},%s]}`, mode, leaf)
					}
					var source option.PlainRuleSet
					require.NoError(t, json.Unmarshal([]byte(`{"rules":[`+rule+`]}`), &source))
					var binary bytes.Buffer
					err := Write(&binary, source, C.RuleSetVersionCurrent)
					require.ErrorContains(t, err, "cannot be represented")
				})
			}
		})
	}
}

func TestBBoxRuleSetExportKeepsNativeConditions(t *testing.T) {
	t.Parallel()
	var source option.PlainRuleSet
	require.NoError(t, json.Unmarshal([]byte(`{"rules":[{"type":"logical","mode":"and","invert":true,"rules":[{"network":["tcp"],"domain_keyword":["example"]},{"ip_cidr":["192.0.2.0/24"]}]}]}`), &source))
	var binary bytes.Buffer
	require.NoError(t, Write(&binary, source, C.RuleSetVersionCurrent))
	recovered, err := Read(bytes.NewReader(binary.Bytes()), true)
	require.NoError(t, err)
	require.EqualValues(t, C.RuleSetVersionCurrent, recovered.Version)
	expectedJSON, err := json.Marshal(source)
	require.NoError(t, err)
	recoveredJSON, err := json.Marshal(recovered.Options)
	require.NoError(t, err)
	require.JSONEq(t, string(expectedJSON), string(recoveredJSON))
}
