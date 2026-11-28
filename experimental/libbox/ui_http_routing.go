package libbox

import (
	"slices"

	"github.com/sagernet/sing-box/experimental/httpdebug"
	"github.com/sagernet/sing-box/option"
)

func uiHTTPRoutingConfig(options option.Options) *httpdebug.HTTPRoutingConfig {
	var config httpdebug.HTTPRoutingConfig
	if options.Experimental != nil && options.Experimental.HTTPRouting != nil {
		config = httpdebug.HTTPRoutingConfig(*options.Experimental.HTTPRouting)
		config.ForceHTTPEngineHosts = append([]string(nil), config.ForceHTTPEngineHosts...)
	}
	if options.Route != nil && uiHasHTTPRequestRules(options.Route.Rules) {
		config.Enabled = true
	}
	if !config.Enabled {
		return nil
	}
	return &config
}

func uiHasHTTPRequestRules(rules []option.Rule) bool {
	for _, rule := range rules {
		if rule.Type == "logical" {
			if uiHasHTTPRequestRules(rule.LogicalOptions.Rules) {
				return true
			}
			continue
		}
		options := rule.DefaultOptions
		// A remote/source rule-set may add request conditions when it loads or
		// refreshes. Validation never downloads it, so reserve the engine now.
		if len(options.HTTPURLRegex) > 0 || len(options.HTTPUserAgent) > 0 || options.Script != "" || options.HTTPExtendedMatching || slices.Contains(options.SurgeProtocol, "HTTP") || slices.Contains(options.SurgeProtocol, "HTTPS") || len(options.RuleSet) > 0 || options.RejectOptions.HTTPResponse != "" {
			return true
		}
	}
	return false
}
