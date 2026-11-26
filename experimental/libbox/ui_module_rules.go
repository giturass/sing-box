package libbox

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

type moduleObject = map[string]any

func moduleFields(text string, nested bool) ([]string, bool) {
	var fields []string
	start, depth := 0, 0
	quoted := false
	for index, char := range text {
		switch {
		case char == '"' && (index == 0 || text[index-1] != '\\'):
			quoted = !quoted
		case !quoted && nested && char == '(':
			depth++
		case !quoted && nested && char == ')':
			depth--
			if depth < 0 {
				return nil, false
			}
		case !quoted && depth == 0 && char == ',':
			fields = append(fields, strings.TrimSpace(text[start:index]))
			start = index + 1
		}
	}
	return append(fields, strings.TrimSpace(text[start:])), depth == 0 && !quoted
}

func moduleUnquote(value string) string {
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		return value[1 : len(value)-1]
	}
	return value
}

func moduleMatch(kind, value string, depth int) moduleObject {
	if value == "" || depth > 32 {
		return nil
	}
	switch kind {
	case "AND", "OR", "NOT":
		if !strings.HasPrefix(value, "(") || !strings.HasSuffix(value, ")") {
			return nil
		}
		parts, ok := moduleFields(value[1:len(value)-1], true)
		if !ok || kind == "NOT" && len(parts) != 1 {
			return nil
		}
		var rules []moduleObject
		for _, part := range parts {
			if len(part) < 2 || part[0] != '(' || part[len(part)-1] != ')' {
				return nil
			}
			fields, ok := moduleFields(part[1:len(part)-1], true)
			if !ok || len(fields) != 2 {
				return nil
			}
			child := moduleMatch(strings.ToUpper(fields[0]), moduleUnquote(fields[1]), depth+1)
			if child == nil {
				return nil
			}
			rules = append(rules, child)
		}
		if kind == "NOT" {
			return moduleObject{"type": "logical", "mode": "and", "rules": rules, "invert": true}
		}
		return moduleObject{"type": "logical", "mode": strings.ToLower(kind), "rules": rules}
	case "DOMAIN", "DOMAIN-KEYWORD", "DOMAIN-SUFFIX", "PROCESS-NAME", "PROCESS-PATH", "PACKAGE-NAME", "SSID", "DOMAIN-WILDCARD":
		key := strings.ReplaceAll(strings.ToLower(kind), "-", "_")
		if kind == "SSID" {
			key = "wifi_ssid"
		}
		if kind == "DOMAIN-WILDCARD" {
			key = "domain_regex"
			value = "(?i)^" + strings.NewReplacer(`\*`, `.*`, `\?`, `.`).Replace(regexp.QuoteMeta(value)) + "$"
		}
		return moduleObject{key: value}
	case "IP-CIDR", "IP-CIDR6", "SRC-IP", "SRC-IP-CIDR":
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			addr, err := netip.ParseAddr(value)
			if err != nil {
				return nil
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		key := "ip_cidr"
		if strings.HasPrefix(kind, "SRC-") {
			key = "source_ip_cidr"
		} else if (kind == "IP-CIDR6") != prefix.Addr().Is6() {
			return nil
		}
		return moduleObject{key: prefix.String()}
	case "DST-PORT", "DEST-PORT", "SRC-PORT":
		key := "port"
		if kind == "SRC-PORT" {
			key = "source_port"
		}
		low, high, ranged := strings.Cut(value, "-")
		first, err := strconv.ParseUint(low, 10, 16)
		if err != nil {
			return nil
		}
		if !ranged {
			return moduleObject{key: first}
		}
		last, err := strconv.ParseUint(high, 10, 16)
		if err != nil || last < first {
			return nil
		}
		return moduleObject{key + "_range": fmt.Sprintf("%d:%d", first, last)}
	case "PROTOCOL", "NETWORK":
		value = strings.ToLower(value)
		switch value {
		case "tcp", "udp", "icmp":
			return moduleObject{"network": value}
		case "quic", "http", "tls", "dns":
			return moduleObject{"protocol": value}
		}
	case "RULE-SET":
		if !strings.Contains(value, "://") {
			return moduleObject{"rule_set": value}
		}
	case "NETWORK-TYPE":
		switch strings.ToLower(value) {
		case "wifi", "cellular", "ethernet", "other":
			return moduleObject{"network_type": strings.ToLower(value)}
		}
	}
	return nil
}

func moduleRule(line string) (moduleObject, string, bool) {
	parts, ok := moduleFields(line, true)
	if !ok {
		return nil, "", false
	}
	if len(parts) == 2 && strings.EqualFold(parts[0], "FINAL") && moduleUnquote(parts[1]) != "" {
		return moduleObject{}, moduleUnquote(parts[1]), true
	}
	if len(parts) < 3 || len(parts) > 4 || moduleUnquote(parts[2]) == "" {
		return nil, "", false
	}
	kind := strings.ToUpper(parts[0])
	if len(parts) == 4 && (!strings.EqualFold(parts[3], "no-resolve") || kind != "IP-CIDR" && kind != "IP-CIDR6") {
		return nil, "", false
	}
	rule := moduleMatch(kind, moduleUnquote(parts[1]), 0)
	return rule, moduleUnquote(parts[2]), rule != nil
}
