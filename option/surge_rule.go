package option

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	C "github.com/sagernet/sing-box/constant"
)

// SurgeRule is an explicitly parsed Surge condition. Its map uses native JSON
// fields, except _surge_set_format, which a module must resolve before decoding.
// This parser is shared by modules and the two plain-text resource formats;
// neither format is a sing-box source JSON / binary rule-set.
type SurgeRule struct {
	Rule              map[string]any
	Policy            string
	UpdateInterval    int64
	HasUpdateInterval bool
}

type SurgeRuleWarning struct {
	Line  int
	Text  string
	Issue string
}

func SurgeRuleFields(text string, nested bool) ([]string, bool) {
	var fields []string
	start, depth := 0, 0
	quoted := false
	for index, char := range text {
		if char == '"' {
			backslashes := 0
			for previous := index - 1; previous >= 0 && text[previous] == '\\'; previous-- {
				backslashes++
			}
			if backslashes%2 == 0 {
				quoted = !quoted
			}
		} else if !quoted {
			switch {
			case nested && char == '(':
				depth++
			case nested && char == ')':
				depth--
				if depth < 0 {
					return nil, false
				}
			case depth == 0 && char == ',':
				fields = append(fields, strings.TrimSpace(text[start:index]))
				start = index + 1
			}
		}
	}
	return append(fields, strings.TrimSpace(text[start:])), depth == 0 && !quoted
}

func SurgeUnquote(value string) string {
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		return value[1 : len(value)-1]
	}
	return value
}

func ParseSurgeRule(line string, withPolicy bool) (SurgeRule, error) {
	fields, ok := surgeRuleFields(line)
	if !ok || len(fields) < 2 {
		return SurgeRule{}, fmt.Errorf("invalid rule fields or unterminated quote")
	}
	return parseSurgeFields(fields, withPolicy, 0)
}

func surgeRuleFields(line string) ([]string, bool) {
	kind, _, _ := strings.Cut(line, ",")
	switch strings.ToUpper(strings.TrimSpace(kind)) {
	case "AND", "OR", "NOT":
		return SurgeRuleFields(line, true)
	default:
		// Only logical rules use parentheses to group fields. A simple URL
		// regex may contain escaped or character-class parentheses; commas
		// still require a double-quoted value, as in Surge's field grammar.
		return SurgeRuleFields(line, false)
	}
}

func parseSurgeFields(fields []string, withPolicy bool, depth int) (SurgeRule, error) {
	kind := strings.ToUpper(fields[0])
	if kind == "FINAL" {
		if !withPolicy || len(fields) != 2 || SurgeUnquote(fields[1]) == "" {
			return SurgeRule{}, fmt.Errorf("FINAL is only supported as a top-level rule without modifiers")
		}
		return SurgeRule{Rule: map[string]any{}, Policy: SurgeUnquote(fields[1])}, nil
	}
	modifierStart := 2
	result := SurgeRule{}
	if withPolicy {
		if len(fields) < 3 || SurgeUnquote(fields[2]) == "" {
			return result, fmt.Errorf("missing rule policy")
		}
		result.Policy, modifierStart = SurgeUnquote(fields[2]), 3
	}
	var err error
	result.Rule, err = surgeMatch(kind, SurgeUnquote(fields[1]), depth)
	if err != nil {
		return result, err
	}
	seen := map[string]bool{}
	for _, raw := range fields[modifierStart:] {
		modifier := strings.ToLower(strings.TrimSpace(raw))
		key, value, hasValue := strings.Cut(modifier, "=")
		if seen[key] {
			return result, fmt.Errorf("duplicate rule modifier: %s", key)
		}
		seen[key] = true
		switch {
		case modifier == "no-resolve" && (kind == "IP-CIDR" || kind == "IP-CIDR6" || kind == "RULE-SET" || kind == "AND" || kind == "OR" || kind == "NOT"):
			ApplySurgeRuleModifier(result.Rule, "surge_no_resolve")
		case modifier == "extended-matching" && (strings.HasPrefix(kind, "DOMAIN") || kind == "URL-REGEX" || kind == "RULE-SET" || kind == "AND" || kind == "OR" || kind == "NOT"):
			ApplySurgeRuleModifier(result.Rule, "http_extended_matching")
		case modifier == "requires-resolve" && kind == "SCRIPT":
			result.Rule["script_requires_resolve"] = true
		case key == "update-interval" && hasValue && (kind == "RULE-SET" || kind == "DOMAIN-SET"):
			interval, parseErr := strconv.ParseInt(value, 10, 64)
			if parseErr != nil || interval == 0 || interval > int64((1<<63-1)/1_000_000_000) || interval < -int64((1<<63-1)/1_000_000_000) {
				return result, fmt.Errorf("invalid rule-set update interval")
			}
			result.UpdateInterval, result.HasUpdateInterval = interval, true
		default:
			return result, fmt.Errorf("unsupported rule modifier: %s", raw)
		}
	}
	return result, nil
}

func ApplySurgeRuleModifier(rule map[string]any, key string) {
	if children, ok := rule["rules"].([]map[string]any); ok {
		for _, child := range children {
			ApplySurgeRuleModifier(child, key)
		}
		return
	}
	rule[key] = true
}

func surgeMatch(kind, value string, depth int) (map[string]any, error) {
	if value == "" || depth > 32 || strings.ContainsAny(value, "\r\n\x00") {
		return nil, fmt.Errorf("invalid or excessively nested rule condition")
	}
	switch kind {
	case "AND", "OR", "NOT":
		if !strings.HasPrefix(value, "(") || !strings.HasSuffix(value, ")") {
			break
		}
		parts, ok := SurgeRuleFields(value[1:len(value)-1], true)
		if !ok || len(parts) == 0 || kind == "NOT" && len(parts) != 1 {
			break
		}
		children := make([]map[string]any, 0, len(parts))
		for _, part := range parts {
			if len(part) < 2 || part[0] != '(' || part[len(part)-1] != ')' {
				return nil, fmt.Errorf("invalid logical sub-rule")
			}
			fields, ok := surgeRuleFields(part[1 : len(part)-1])
			if !ok || len(fields) < 2 {
				return nil, fmt.Errorf("invalid logical sub-rule fields")
			}
			parsed, err := parseSurgeFields(fields, false, depth+1)
			if err != nil || parsed.HasUpdateInterval {
				if err == nil {
					err = fmt.Errorf("update-interval is not a logical sub-rule modifier")
				}
				return nil, err
			}
			children = append(children, parsed.Rule)
		}
		if kind == "NOT" {
			return map[string]any{"type": "logical", "mode": "and", "rules": children, "invert": true}, nil
		}
		return map[string]any{"type": "logical", "mode": strings.ToLower(kind), "rules": children}, nil
	case "DOMAIN", "DOMAIN-KEYWORD", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD":
		key := strings.ReplaceAll(strings.ToLower(kind), "-", "_")
		if kind == "DOMAIN-WILDCARD" {
			key = "domain_regex"
			var err error
			value, err = surgeDomainWildcardRegex(value)
			if err != nil {
				return nil, err
			}
		}
		return map[string]any{key: value}, nil
	case "PROCESS-NAME", "PROCESS-PATH", "PACKAGE-NAME", "SSID":
		key := strings.ReplaceAll(strings.ToLower(kind), "-", "_")
		if kind == "SSID" {
			key = "wifi_ssid"
		}
		return map[string]any{key: value}, nil
	case "URL-REGEX":
		return map[string]any{"http_url_regex": value}, nil
	case "USER-AGENT":
		return map[string]any{"http_user_agent": value}, nil
	case "SCRIPT":
		return map[string]any{"script": value}, nil
	case "IP-CIDR", "IP-CIDR6", "SRC-IP", "SRC-IP-CIDR":
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, addressErr := netip.ParseAddr(value)
			if addressErr != nil {
				break
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		if strings.HasPrefix(kind, "SRC-") {
			return map[string]any{"source_ip_cidr": prefix.String()}, nil
		}
		if (kind == "IP-CIDR6") != prefix.Addr().Is6() {
			break
		}
		return map[string]any{"ip_cidr": prefix.String(), "surge_ip_cidr": true}, nil
	case "DST-PORT", "DEST-PORT", "SRC-PORT":
		key := "port"
		if kind == "SRC-PORT" {
			key = "source_port"
		}
		low, high, ranged := strings.Cut(value, "-")
		first, err := strconv.ParseUint(low, 10, 16)
		if err != nil {
			break
		}
		if !ranged {
			return map[string]any{key: first}, nil
		}
		last, err := strconv.ParseUint(high, 10, 16)
		if err != nil || last < first {
			break
		}
		return map[string]any{key + "_range": fmt.Sprintf("%d:%d", first, last)}, nil
	case "PROTOCOL":
		// Surge's case-sensitive protocol names describe the original request.
		// HTTP/HTTPS cannot be folded into sing-box's post-MITM http sniffer;
		// DNS/DO* identify Surge's own DNS traffic, which B-box does not expose.
		switch value {
		case "HTTP", "HTTPS", "TCP", "UDP", "QUIC", "STUN":
			return map[string]any{"surge_protocol": value}, nil
		default:
			return nil, fmt.Errorf("unsupported or invalid Surge PROTOCOL value: %s", value)
		}
	case "NETWORK":
		switch strings.ToLower(value) {
		case "tcp", "udp", "icmp":
			return map[string]any{"network": strings.ToLower(value)}, nil
		}
	case "RULE-SET", "DOMAIN-SET":
		if kind == "RULE-SET" && (strings.EqualFold(value, "SYSTEM") || strings.EqualFold(value, "LAN")) {
			return nil, fmt.Errorf("Surge built-in rule-set %s is not an Android / sing-box rule-set", value)
		}
		format := C.RuleSetFormatSurgeRules
		if kind == "DOMAIN-SET" {
			format = C.RuleSetFormatSurgeDomains
		}
		return map[string]any{"rule_set": value, "_surge_set_format": format}, nil
	case "NETWORK-TYPE":
		switch strings.ToLower(value) {
		case "wifi", "cellular", "ethernet", "other":
			return map[string]any{"network_type": strings.ToLower(value)}, nil
		}
	}
	return nil, fmt.Errorf("unsupported or invalid rule condition: %s", kind)
}

// DOMAIN-WILDCARD is a host glob, not a regular expression. Basic positive
// ASCII classes and ascending ranges are supported; class negation, escapes
// and POSIX classes are rejected rather than guessed or treated as literals.
func surgeDomainWildcardRegex(pattern string) (string, error) {
	characters := []rune(pattern)
	var expression strings.Builder
	expression.WriteString("(?i)^")
	for index := 0; index < len(characters); index++ {
		switch character := characters[index]; character {
		case '*':
			expression.WriteString(".*")
		case '?':
			expression.WriteByte('.')
		case '[':
			end := index + 1
			for end < len(characters) && characters[end] != ']' {
				end++
			}
			if end == len(characters) || end == index+1 {
				return "", fmt.Errorf("DOMAIN-WILDCARD: unclosed or empty character class")
			}
			class := characters[index+1 : end]
			expression.WriteByte('[')
			for part := 0; part < len(class); part++ {
				character := class[part]
				if character == '-' {
					if part != 0 && part != len(class)-1 {
						return "", fmt.Errorf("DOMAIN-WILDCARD: ambiguous character class range")
					}
					expression.WriteString(`\-`)
					continue
				}
				if !surgeWildcardClassCharacter(character) {
					return "", fmt.Errorf("DOMAIN-WILDCARD: unsupported character class syntax")
				}
				expression.WriteString(regexp.QuoteMeta(string(character)))
				if part+2 < len(class) && class[part+1] == '-' {
					last := class[part+2]
					if !surgeWildcardClassCharacter(last) || last < character {
						return "", fmt.Errorf("DOMAIN-WILDCARD: invalid character class range")
					}
					expression.WriteByte('-')
					expression.WriteString(regexp.QuoteMeta(string(last)))
					part += 2
				}
			}
			expression.WriteByte(']')
			index = end
		case ']':
			return "", fmt.Errorf("DOMAIN-WILDCARD: unmatched closing bracket")
		case '\\':
			return "", fmt.Errorf("DOMAIN-WILDCARD: escaped glob syntax is not supported")
		default:
			expression.WriteString(regexp.QuoteMeta(string(character)))
		}
	}
	expression.WriteByte('$')
	result := expression.String()
	if _, err := regexp.Compile(result); err != nil {
		return "", fmt.Errorf("DOMAIN-WILDCARD: %w", err)
	}
	return result, nil
}

func surgeWildcardClassCharacter(character rune) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '.' || character == '_'
}

func SurgeRuleContainsSet(rule map[string]any) bool {
	if _, found := rule["rule_set"]; found {
		return true
	}
	if children, ok := rule["rules"].([]map[string]any); ok {
		for _, child := range children {
			if SurgeRuleContainsSet(child) {
				return true
			}
		}
	}
	return false
}

// ParseSurgeRuleSet follows Surge's warn-and-skip treatment of unsupported
// complete lines. Logical conditions are parsed atomically: no child is removed.
// Set references are outside B-box's non-nested rule-set scope.
func ParseSurgeRuleSet(content []byte, format string) (PlainRuleSet, []SurgeRuleWarning, error) {
	if !utf8.Valid(content) {
		return PlainRuleSet{}, nil, fmt.Errorf("Surge rule-set must be UTF-8 text")
	}
	result := PlainRuleSet{}
	var warnings []SurgeRuleWarning
	for index, raw := range strings.Split(strings.TrimPrefix(string(content), "\ufeff"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || format == C.RuleSetFormatSurgeRules && strings.HasPrefix(line, ";") {
			continue
		}
		var rule map[string]any
		var err error
		if format == C.RuleSetFormatSurgeDomains {
			if !validSurgeDomainSetName(line) {
				err = fmt.Errorf("DOMAIN-SET entries must be plain domains, with an optional leading dot")
			} else if strings.HasPrefix(line, ".") {
				rule = map[string]any{"domain_suffix": strings.ToLower(line[1:])}
			} else {
				rule = map[string]any{"domain": strings.ToLower(line)}
			}
		} else if format == C.RuleSetFormatSurgeRules {
			var parsed SurgeRule
			parsed, err = ParseSurgeRule(line, false)
			rule = parsed.Rule
			if err == nil && (SurgeRuleContainsSet(rule) || parsed.HasUpdateInterval) {
				err = fmt.Errorf("nested RULE-SET / DOMAIN-SET references are not supported")
			}
		} else {
			return result, warnings, fmt.Errorf("unknown Surge rule-set format: %s", format)
		}
		if err == nil {
			encoded, encodeErr := json.Marshal(rule)
			if encodeErr != nil {
				return result, warnings, encodeErr
			}
			var headless HeadlessRule
			decoder := json.NewDecoder(bytes.NewReader(encoded))
			decoder.DisallowUnknownFields()
			err = decoder.Decode(&headless)
			if err == nil {
				result.Rules = append(result.Rules, headless)
			}
		}
		if err != nil {
			warnings = append(warnings, SurgeRuleWarning{Line: index + 1, Text: line, Issue: err.Error()})
		}
	}
	if len(result.Rules) == 0 && len(warnings) > 0 {
		return result, warnings, fmt.Errorf("Surge rule-set contains no supported rules")
	}
	ApplySurgeDomainSetExtendedMatching(result.Rules)
	return result, warnings, nil
}

// A module's declared name takes precedence; an undeclared module name keeps
// its profile name and is then validated by the runtime's ScriptItem constructor.
func NamespaceSurgeRuleSetScripts(rules []HeadlessRule, namespace string, declarations map[string]bool) {
	if namespace == "" {
		return
	}
	for index := range rules {
		if rules[index].Type == C.RuleTypeLogical {
			NamespaceSurgeRuleSetScripts(rules[index].LogicalOptions.Rules, namespace, declarations)
		} else if name := rules[index].DefaultOptions.Script; name != "" && declarations[namespace+name] {
			rules[index].DefaultOptions.Script = namespace + name
		}
	}
}

// Surge applies extended-matching to every domain entry in a set when any
// domain entry requests it. This is separate from sing-box's native grouping.
func ApplySurgeDomainSetExtendedMatching(rules []HeadlessRule) {
	var contains func([]HeadlessRule) bool
	contains = func(rules []HeadlessRule) bool {
		for _, rule := range rules {
			if rule.Type == C.RuleTypeLogical {
				if contains(rule.LogicalOptions.Rules) {
					return true
				}
				continue
			}
			value := rule.DefaultOptions
			if value.HTTPExtendedMatching && (len(value.Domain)+len(value.DomainSuffix)+len(value.DomainKeyword)+len(value.DomainRegex) > 0) {
				return true
			}
		}
		return false
	}
	if !contains(rules) {
		return
	}
	var apply func([]HeadlessRule)
	apply = func(rules []HeadlessRule) {
		for index := range rules {
			if rules[index].Type == C.RuleTypeLogical {
				apply(rules[index].LogicalOptions.Rules)
				continue
			}
			value := &rules[index].DefaultOptions
			if len(value.Domain)+len(value.DomainSuffix)+len(value.DomainKeyword)+len(value.DomainRegex) > 0 {
				value.HTTPExtendedMatching = true
			}
		}
	}
	apply(rules)
}

func validSurgeDomainSetName(value string) bool {
	value = strings.TrimPrefix(value, ".")
	if value == "" || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, char := range label {
			if char != '-' && !(char >= 'a' && char <= 'z') && !(char >= 'A' && char <= 'Z') && !(char >= '0' && char <= '9') {
				return false
			}
		}
	}
	return true
}
