package libbox

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/httpdebug"
	"github.com/sagernet/sing-box/option"
)

type moduleObject = map[string]any

func moduleFields(text string, nested bool) ([]string, bool) {
	return option.SurgeRuleFields(text, nested)
}
func moduleUnquote(value string) string { return option.SurgeUnquote(value) }

func moduleRule(line string) (moduleObject, string, bool) {
	parsed, err := option.ParseSurgeRule(line, true)
	return parsed.Rule, parsed.Policy, err == nil
}

func moduleRulePolicy(rule moduleObject, policy string) {
	switch strings.ToUpper(policy) {
	case "REJECT":
		rule["action"] = "reject"
	case "REJECT-DROP":
		rule["action"], rule["method"] = "reject", "drop"
	case "REJECT-NO-DROP":
		rule["action"], rule["no_drop"] = "reject", true
	case "REJECT-200", "REJECT-DICT", "REJECT-TINYGIF":
		rule["action"], rule["http_response"] = "reject", strings.ToLower(policy)
	default:
		rule["outbound"] = policy
	}
}

func (description *moduleDescription) addForceHTTPHosts(line, value string) {
	mode := "replace"
	for _, token := range []string{"%APPEND%", "%INSERT%"} {
		if strings.HasPrefix(value, token) {
			mode, value = token, strings.TrimSpace(value[len(token):])
			break
		}
	}
	hosts := []string{}
	for _, raw := range strings.Split(value, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		// Normalization preserves a bare host without adding port 443. The
		// forced plaintext engine interprets the shared Host List grammar at 80.
		host, err := httpdebug.NormalizeMITMHost(raw)
		if err != nil {
			issue := fmt.Errorf("invalid forced HTTP host %q: %w", raw, err)
			description.Lines["ignored"] = append(description.Lines["ignored"], moduleLine{Text: line, Issue: issue.Error()})
			if mode == "replace" || strings.HasPrefix(raw, "-") {
				description.forceHTTPHosts.invalid = issue
				return
			}
			continue
		}
		hosts = append(hosts, host)
	}
	if mode != "replace" && len(hosts) == 0 {
		return
	}
	patch := &description.forceHTTPHosts
	switch {
	case mode == "replace":
		patch.insert, patch.append, patch.replace = nil, nil, hosts
	case mode == "%INSERT%" && patch.replace != nil:
		patch.replace = append(hosts, patch.replace...)
	case mode == "%APPEND%" && patch.replace != nil:
		patch.replace = append(patch.replace, hosts...)
	case mode == "%INSERT%":
		patch.insert = append(hosts, patch.insert...)
	default:
		patch.append = append(patch.append, hosts...)
	}
	description.Lines["general"] = append(description.Lines["general"], moduleLine{Text: line})
}

// Resource names are resolved with the original profile's native tags in hand.
// Surge inline names take precedence; a pre-existing native tag is an explicit
// B-box compatibility entry, while URLs / module attachments use Surge text.
func (description *moduleDescription) resolveModuleRuleSets(source option.ModuleOptions, native, used map[string]bool, resourceFormats map[string]string, resourceIntervals map[string]int64) error {
	definitions := map[string]moduleObject{}
	var order []string
	var resolve func(moduleObject) error
	resolve = func(rule moduleObject) error {
		if children, ok := rule["rules"].([]moduleObject); ok {
			for _, child := range children {
				if err := resolve(child); err != nil {
					return err
				}
			}
			return nil
		}
		format, hasReference := rule["_surge_set_format"].(string)
		if !hasReference {
			return nil
		}
		name, _ := rule["rule_set"].(string)
		interval, hasInterval := rule["_surge_set_update_interval"].(int64)
		delete(rule, "_surge_set_format")
		delete(rule, "_surge_set_update_interval")
		if name == "" {
			return fmt.Errorf("empty module rule-set reference")
		}
		var definition moduleObject
		var identity string
		if inline, found := description.inlineRuleSets[name]; found && format == C.RuleSetFormatSurgeRules {
			if issue := description.inlineRuleSetIssues[name]; issue != nil {
				return fmt.Errorf("inline rule-set %q: %w", name, issue)
			}
			if len(inline) == 0 {
				return fmt.Errorf("inline rule-set %q has no supported rules", name)
			}
			data, err := json.Marshal(inline)
			if err != nil {
				return err
			}
			var rules []option.HeadlessRule
			if err := json.Unmarshal(data, &rules); err != nil {
				return fmt.Errorf("inline rule-set %q: %w", name, err)
			}
			option.ApplySurgeDomainSetExtendedMatching(rules)
			inline, err = moduleHeadlessRuleMaps(rules)
			if err != nil {
				return err
			}
			identity = "inline:" + source.ID + ":" + name
			definition = moduleObject{"type": "inline", "rules": inline}
			if hasInterval {
				return fmt.Errorf("update-interval cannot apply to an inline rule-set")
			}
		} else if native[name] && format == C.RuleSetFormatSurgeRules && !strings.Contains(name, "://") {
			if hasInterval {
				return fmt.Errorf("update-interval cannot apply to an existing sing-box rule-set tag")
			}
			return nil
		} else {
			remote, encoded, err := moduleResource(source, name)
			if err != nil {
				return err
			}
			if remote != "" {
				identity = remote
				definition = moduleObject{"type": "remote", "format": format, "url": remote}
				if format == C.RuleSetFormatSurgeRules {
					definition["script_namespace"] = source.ID + "/"
				}
				if hasInterval {
					definition["update_interval"] = fmt.Sprintf("%ds", interval)
				}
			} else {
				identity = "attachment:" + source.ID + ":" + name
				data, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					return fmt.Errorf("invalid rule-set attachment %q: %w", name, err)
				}
				set, warnings, err := option.ParseSurgeRuleSet(data, format)
				if err != nil {
					return err
				}
				for _, warning := range warnings {
					description.Lines["ignored"] = append(description.Lines["ignored"], moduleLine{Text: name + ":" + fmt.Sprint(warning.Line) + ": " + warning.Text, Issue: warning.Issue})
				}
				if len(set.Rules) == 0 {
					return fmt.Errorf("rule-set attachment %q has no supported rules", name)
				}
				maps, err := moduleHeadlessRuleMaps(set.Rules)
				if err != nil {
					return err
				}
				definition = moduleObject{"type": "inline", "rules": maps}
				if hasInterval {
					return fmt.Errorf("update-interval cannot apply to a module attachment")
				}
			}
			if previous := resourceFormats[identity]; previous != "" && previous != format {
				return fmt.Errorf("one Surge rule-set resource cannot use both RULE-SET and DOMAIN-SET: %s", name)
			}
			resourceFormats[identity] = format
			if remote != "" {
				effectiveInterval := int64(86400)
				if hasInterval {
					effectiveInterval = interval
				}
				if effectiveInterval < 0 {
					effectiveInterval = -1
				}
				if previous, found := resourceIntervals[identity]; found && previous != effectiveInterval {
					return fmt.Errorf("conflicting update intervals for one Surge rule-set resource: %s", name)
				}
				resourceIntervals[identity] = effectiveInterval
			}
		}
		key := format + "\x00" + identity
		if existing := definitions[key]; existing != nil {
			definition = existing
		} else {
			sum := sha256.Sum256([]byte(source.ID + "\x00" + key))
			base := "module-rule-set-" + hex.EncodeToString(sum[:8])
			tag := base
			for number := 2; used[tag]; number++ {
				tag = fmt.Sprintf("%s-%d", base, number)
			}
			used[tag] = true
			definition["tag"] = tag
			definitions[key] = definition
			order = append(order, key)
		}
		rule["rule_set"] = definition["tag"]
		return nil
	}
	for _, raw := range description.values["rules"] {
		if err := resolve(raw.(moduleObject)); err != nil {
			return err
		}
	}
	for _, key := range order {
		definition := definitions[key]
		description.values["rule_set"] = append(description.values["rule_set"], definition)
	}
	return nil
}

func moduleHeadlessRuleMaps(rules []option.HeadlessRule) ([]moduleObject, error) {
	data, err := json.Marshal(rules)
	if err != nil {
		return nil, err
	}
	var result []moduleObject
	err = json.Unmarshal(data, &result)
	return result, err
}
