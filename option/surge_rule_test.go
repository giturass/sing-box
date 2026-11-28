package option

import (
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

func TestSurgeURLRegexFieldsPreserveLiteralParenthesesAndQuotedCommas(t *testing.T) {
	t.Parallel()
	for _, sample := range []struct{ field, pattern string }{
		{`^https://x/[(]foo`, `^https://x/[(]foo`},
		{`^https://x/[^)]*`, `^https://x/[^)]*`},
		{`^https://x/\(foo`, `^https://x/\(foo`},
		{`^https://x/foo\)`, `^https://x/foo\)`},
		{`"^https://x/(a|b),?c"`, `^https://x/(a|b),?c`},
	} {
		line := "URL-REGEX," + sample.field
		condition, err := ParseSurgeRule(line, false)
		require.NoError(t, err, line)
		require.Equal(t, sample.pattern, condition.Rule["http_url_regex"])
		require.Empty(t, condition.Policy)
		withPolicy, err := ParseSurgeRule(line+",DIRECT", true)
		require.NoError(t, err, line)
		require.Equal(t, sample.pattern, withPolicy.Rule["http_url_regex"])
		require.Equal(t, "DIRECT", withPolicy.Policy)
		shared, warnings, err := ParseSurgeRuleSet([]byte(line), C.RuleSetFormatSurgeRules)
		require.NoError(t, err)
		require.Empty(t, warnings)
		require.Len(t, shared.Rules, 1)
		require.Equal(t, []string{sample.pattern}, []string(shared.Rules[0].DefaultOptions.HTTPURLRegex))
	}
	logical, err := ParseSurgeRule(`AND,((DOMAIN,x),(URL-REGEX,"^https://x/(a|b),?c")),DIRECT`, true)
	require.NoError(t, err)
	require.Equal(t, C.RuleTypeLogical, logical.Rule["type"])
	children := logical.Rule["rules"].([]map[string]any)
	require.Len(t, children, 2)
	require.Equal(t, `^https://x/(a|b),?c`, children[1]["http_url_regex"])
	_, err = ParseSurgeRule(`AND,((DOMAIN,x),(DOMAIN,y),DIRECT`, true)
	require.Error(t, err, "logical parentheses must remain structural")
	for _, policy := range []bool{false, true} {
		line := `URL-REGEX,^https://x/(a|b),?c`
		if policy {
			line += ",DIRECT"
		}
		_, err = ParseSurgeRule(line, policy)
		require.Error(t, err, "commas in a regex still require double quotes")
	}
	shared, warnings, err := ParseSurgeRuleSet([]byte(strings.Join([]string{`URL-REGEX,^https://x/[(]foo`, `URL-REGEX,^https://x/(a|b),?c`}, "\n")), C.RuleSetFormatSurgeRules)
	require.NoError(t, err)
	require.Len(t, shared.Rules, 1)
	require.Len(t, warnings, 1)
	require.Equal(t, 2, warnings[0].Line)
}
