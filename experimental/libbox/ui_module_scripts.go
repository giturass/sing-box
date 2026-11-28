package libbox

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/experimental/httpdebug"
)

func moduleScriptKey(kind string) string {
	if kind == "rule" || kind == "dns" {
		return "script_" + kind
	}
	return kind
}

func moduleDNSHost(line string) (moduleObject, error) {
	host, value, found := strings.Cut(line, "=")
	if !found {
		return nil, fmt.Errorf("expected a hostname or pattern and IP addresses or script:name")
	}
	pattern, err := httpdebug.NormalizeDNSHostPattern(host)
	if err != nil {
		return nil, err
	}
	entry := moduleObject{"pattern": pattern}
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "script:") {
		name := strings.TrimSpace(strings.TrimPrefix(value, "script:"))
		if name == "" || strings.ContainsAny(name, ",\r\n") {
			return nil, fmt.Errorf("missing DNS script name")
		}
		entry["script"] = name
		return entry, nil
	}
	addresses := []string{}
	for _, item := range strings.Split(value, ",") {
		address, err := netip.ParseAddr(strings.TrimSpace(item))
		if err != nil || address.Zone() != "" {
			return nil, fmt.Errorf("not an IP address")
		}
		addresses = append(addresses, address.Unmap().String())
	}
	entry["addresses"] = addresses
	return entry, nil
}

// Modules retain their original declaration names in the UI and text. The
// effective profile gives each module its own names so identical names from
// another module cannot redirect a SCRIPT condition or DNS Host entry.
func namespaceModuleScripts(parsed *moduleDescription, prefix string) {
	names := map[string]bool{}
	dnsNames := map[string]bool{}
	for _, group := range []string{"script_rule", "script_dns"} {
		for _, value := range parsed.values[group] {
			entry := value.(moduleObject)
			name, _ := entry["name"].(string)
			if group == "script_rule" {
				names[name] = true
			} else {
				dnsNames[name] = true
			}
			entry["name"] = prefix + name
		}
	}
	var walk func(moduleObject)
	walk = func(entry moduleObject) {
		if name, _ := entry["script"].(string); names[name] {
			entry["script"] = prefix + name
		}
		switch children := entry["rules"].(type) {
		case []any:
			for _, child := range children {
				if object, ok := child.(moduleObject); ok {
					walk(object)
				}
			}
		case []moduleObject:
			for _, child := range children {
				walk(child)
			}
		}
	}
	for _, group := range []string{"rules", "rule_set"} {
		for _, value := range parsed.values[group] {
			walk(value.(moduleObject))
		}
	}
	for _, value := range parsed.values["dns_host"] {
		entry := value.(moduleObject)
		if name, _ := entry["script"].(string); dnsNames[name] {
			entry["script"] = prefix + name
		}
	}
}
