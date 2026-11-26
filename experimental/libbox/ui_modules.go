package libbox

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/sagernet/sing-box/experimental/httpdebug"
	"github.com/sagernet/sing-box/option"
)

type moduleLine struct {
	Text  string `json:"text"`
	Issue string `json:"issue,omitempty"`
	Kind  string `json:"kind,omitempty"`
	Index int    `json:"index,omitempty"`
}

type moduleArgument struct {
	Name    string `json:"name"`
	Default string `json:"default"`
}

type moduleDescription struct {
	Name         string                  `json:"name"`
	Description  string                  `json:"description"`
	System       string                  `json:"system"`
	ArgumentHelp string                  `json:"argumentHelp"`
	Arguments    []moduleArgument        `json:"arguments"`
	Lines        map[string][]moduleLine `json:"lines"`
	HasScripts   bool                    `json:"hasScripts"`
	Panels       []modulePanel           `json:"panels,omitempty"`
	values       map[string][]any
	hosts        moduleHostPatch
}

type moduleHostPatch struct {
	insert, append, replace []string
	invalid                 error
}

func (description *moduleDescription) addHosts(line, value string) {
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
		host, err := httpdebug.NormalizeMITMHost(raw)
		if err != nil {
			issue := fmt.Errorf("invalid MITM host %q: %w", raw, err)
			description.Lines["ignored"] = append(description.Lines["ignored"], moduleLine{Text: line, Issue: issue.Error()})
			if mode == "replace" || strings.HasPrefix(raw, "-") {
				description.hosts.invalid = issue
				return
			}
			continue
		}
		hosts = append(hosts, host)
	}
	if mode != "replace" && len(hosts) == 0 {
		return
	}
	patch := &description.hosts
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
	description.Lines["mitm"] = append(description.Lines["mitm"], moduleLine{Text: line})
}

var moduleParam = regexp.MustCompile(`^[a-z][a-z0-9-]*\s*=`)
var moduleVariable = regexp.MustCompile(`\{\{\{([^{}]+)\}\}\}`)

func moduleResource(source option.ModuleOptions, name string) (remote, encoded string, err error) {
	ref, err := url.Parse(name)
	if err != nil || name == "" {
		return "", "", fmt.Errorf("invalid resource path")
	}
	if source.URL != "" {
		base, err := url.Parse(source.URL)
		if err != nil || base.Hostname() == "" || base.Scheme != "https" && base.Scheme != "http" {
			return "", "", fmt.Errorf("invalid module URL")
		}
		ref = base.ResolveReference(ref)
	}
	if (ref.Scheme == "http" || ref.Scheme == "https") && ref.Hostname() != "" {
		return ref.String(), "", nil
	}
	if source.URL == "" && ref.Scheme == "" {
		if data, ok := source.Attachments[name]; ok && path.Base(name) == name && name != "." && name != ".." {
			return "", data, nil
		}
	}
	return "", "", fmt.Errorf("missing module attachment or unsupported URL: %s", name)
}

func moduleScript(source option.ModuleOptions, line string) (string, moduleObject, error) {
	name, text, found := strings.Cut(line, "=")
	name = strings.TrimSpace(name)
	options := map[string]string{}
	if first, rest, legacy := strings.Cut(line, " "); legacy && (first == "http-request" || first == "http-response" || first == "cron" || first == "event" || first == "generic") && !strings.HasPrefix(strings.TrimSpace(rest), "=") {
		rest = strings.TrimSpace(rest)
		end := strings.IndexAny(rest, " \t")
		if strings.HasPrefix(rest, `"`) {
			end = strings.IndexByte(rest[1:], '"')
			if end >= 0 {
				end += 2
			}
		}
		if end < 0 {
			return "", nil, fmt.Errorf("missing script parameters")
		}
		value := moduleUnquote(rest[:end])
		name = ""
		options["type"] = first
		text = strings.TrimSpace(rest[end:])
		switch first {
		case "cron":
			options["cronexp"] = value
		case "event":
			options["event-name"] = value
		case "generic":
			name = value
		default:
			options["pattern"] = value
		}
	} else if !found {
		return "", nil, fmt.Errorf("expected a script declaration")
	}
	fields, ok := moduleFields(text, false)
	if !ok {
		return "", nil, fmt.Errorf("unterminated quote")
	}
	key := ""
	for _, field := range fields {
		if moduleParam.MatchString(field) {
			var value string
			key, value, _ = strings.Cut(field, "=")
			key = strings.TrimSpace(key)
			options[key] = strings.TrimSpace(value)
		} else if key != "" {
			options[key] += "," + field
		} else {
			return "", nil, fmt.Errorf("invalid script parameter")
		}
	}
	for key, value := range options {
		options[key] = moduleUnquote(value)
	}
	remote, data, err := moduleResource(source, options["script-path"])
	if err != nil {
		return "", nil, err
	}
	if name == "" {
		name = path.Base(options["script-path"])
	}
	entry := moduleObject{"name": name}
	if remote != "" {
		entry["script_path"] = remote
	} else {
		body, err := base64.StdEncoding.DecodeString(data)
		if err != nil || !utf8.Valid(body) {
			return "", nil, fmt.Errorf("invalid UTF-8 script attachment")
		}
		entry["source"] = string(body)
	}
	for _, key := range slices.Sorted(maps.Keys(options)) {
		value := options[key]
		switch key {
		case "timeout":
			seconds, err := strconv.ParseFloat(value, 64)
			if err != nil || !(seconds > 0 && seconds <= float64(math.MaxInt32)/1000) || math.Round(seconds*1000) < 1 {
				return "", nil, fmt.Errorf("invalid timeout")
			}
			entry["timeout_ms"] = int(math.Round(seconds * 1000))
		case "script-update-interval", "max-size":
			number, err := strconv.ParseInt(value, 10, 64)
			if err != nil || number == 0 || number < -1 || key == "script-update-interval" && number < 1 {
				return "", nil, fmt.Errorf("invalid %s", key)
			}
			if key == "max-size" {
				entry["max_body_bytes"] = number
			} else if remote != "" {
				entry["script_update_interval"] = number
			}
		case "argument":
			entry["argument"] = value
		case "debug", "requires-body", "binary-body-mode", "full-header-mode":
			if value == "true" || value == "1" {
				entry[map[string]string{"debug": "debug", "requires-body": "requires_body", "binary-body-mode": "binary_body", "full-header-mode": "full_headers"}[key]] = true
			} else if value != "false" && value != "0" {
				return "", nil, fmt.Errorf("invalid %s", key)
			}
		case "type", "script-path", "pattern", "event-name", "cronexp":
		default:
			return "", nil, fmt.Errorf("unsupported script parameter: %s", key)
		}
	}
	kind := options["type"]
	switch kind {
	case "http-request", "http-response":
		if options["pattern"] == "" {
			return "", nil, fmt.Errorf("missing pattern")
		}
		entry["phase"] = strings.TrimPrefix(kind, "http-")
		entry["pattern"] = options["pattern"]
		kind = "http"
	case "cron":
		entry["cron"] = options["cronexp"]
	case "event":
		entry["event"] = options["event-name"]
	case "", "generic":
		kind = "generic"
	default:
		return "", nil, fmt.Errorf("unsupported script type: %s", kind)
	}
	return kind, entry, nil
}

func readModule(source option.ModuleOptions) moduleDescription {
	result := moduleDescription{Lines: map[string][]moduleLine{}, values: map[string][]any{}}
	lines := strings.Split(strings.TrimPrefix(source.Content, "\ufeff"), "\n")
	args := map[string]string{}
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "#!") {
			continue
		}
		key, value, ok := strings.Cut(line[2:], "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "name":
			result.Name = value
		case "desc":
			result.Description = value
		case "system":
			result.System = value
		case "arguments-desc":
			result.ArgumentHelp = strings.ReplaceAll(value, `\n`, "\n")
		case "arguments":
			fields, _ := moduleFields(value, false)
			for _, field := range fields {
				name, fallback, _ := strings.Cut(field, ":")
				name = strings.TrimSpace(name)
				if _, exists := args[name]; name == "" || exists {
					continue
				}
				fallback = moduleUnquote(strings.TrimSpace(fallback))
				result.Arguments = append(result.Arguments, moduleArgument{name, fallback})
				args[name] = fallback
				if override, ok := source.Arguments[name]; ok {
					args[name] = override
				}
			}
		}
	}
	section := ""
	var panels []modulePanel
	conditional := 0
	extraBudget := 8 << 20
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		directive := strings.ToLower(line)
		if strings.HasPrefix(directive, "#!if ") || strings.HasPrefix(directive, "#!if=") {
			conditional++
			continue
		}
		if directive == "#!endif" && conditional > 0 {
			conditional--
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		if conditional > 0 {
			result.Lines["ignored"] = append(result.Lines["ignored"], moduleLine{Text: line, Issue: "Conditional block"})
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		exceeded := false
		expanded := moduleVariable.ReplaceAllStringFunc(line, func(token string) string {
			if value, ok := args[token[3:len(token)-3]]; ok {
				extra := max(0, len(value)-len(token))
				if extra > extraBudget {
					exceeded = true
					return token
				}
				extraBudget -= extra
				return value
			}
			return token
		})
		if exceeded {
			result.Lines["ignored"] = append(result.Lines["ignored"], moduleLine{Text: line, Issue: "Module argument expansion is too large"})
			continue
		}
		if section == "script" {
			result.HasScripts = true
		}
		line = strings.TrimSpace(expanded)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		group := section
		display := moduleLine{Text: line}
		var err error
		switch section {
		case "panel":
			var panel modulePanel
			panel, err = parseModulePanel(line)
			if err == nil {
				panels = append(panels, panel)
				continue
			}
		case "rule":
			if kind, _, _ := strings.Cut(line, ","); strings.EqualFold(strings.TrimSpace(kind), "URL-REGEX") {
				fields, ok := moduleFields(line, true)
				if !ok || len(fields) != 3 || moduleUnquote(fields[1]) == "" {
					err = fmt.Errorf("invalid URL-REGEX rule")
					break
				}
				action := map[string]string{"REJECT": "reject", "REJECT-200": "reject-200", "REJECT-DICT": "reject-dict", "REJECT-TINYGIF": "reject-tinygif"}[strings.ToUpper(fields[2])]
				if action == "" {
					err = fmt.Errorf("unsupported URL-REGEX policy")
					break
				}
				entry := moduleObject{"pattern": moduleUnquote(fields[1]), "action": action}
				var check httpdebug.RewriteConfig
				encoded, _ := json.Marshal(moduleObject{"url_rewrite": []any{entry}})
				err = json.Unmarshal(encoded, &check)
				if err == nil {
					group = "url rewrite"
					result.values["url_rewrite"] = append(result.values["url_rewrite"], entry)
				}
				break
			}
			rule, policy, ok := moduleRule(line)
			if !ok {
				err = fmt.Errorf("unsupported route condition or modifier")
				break
			}
			switch strings.ToUpper(policy) {
			case "REJECT":
				rule["action"] = "reject"
			case "REJECT-DROP":
				rule["action"] = "reject"
				rule["method"] = "drop"
			case "REJECT-NO-DROP":
				rule["action"] = "reject"
				rule["no_drop"] = true
			default:
				rule["outbound"] = policy
			}
			result.values["rules"] = append(result.values["rules"], rule)
		case "host":
			host, addresses, ok := strings.Cut(line, "=")
			host = strings.TrimSpace(host)
			if !ok || !moduleHostname.MatchString(host) {
				err = fmt.Errorf("expected an exact hostname and IP addresses")
				break
			}
			answers := map[string][]string{}
			for _, item := range strings.Split(addresses, ",") {
				addr, parseErr := netip.ParseAddr(strings.TrimSpace(item))
				if parseErr != nil {
					err = fmt.Errorf("not an IP address")
					break
				}
				record := "A"
				if addr.Is6() {
					record = "AAAA"
				}
				answers[record] = append(answers[record], fmt.Sprintf("%s. 60 IN %s %s", strings.TrimSuffix(host, "."), record, addr))
			}
			if err == nil {
				for _, record := range []string{"A", "AAAA"} {
					result.values["dns"] = append(result.values["dns"], moduleObject{"domain": strings.TrimSuffix(host, "."), "query_type": record, "action": "predefined", "answer": answers[record]})
				}
			}
		case "mitm":
			key, value, ok := strings.Cut(line, "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(key), "hostname") {
				err = fmt.Errorf("unsupported MITM setting")
				break
			}
			result.addHosts(line, strings.TrimSpace(value))
			continue
		case "url rewrite", "body rewrite", "header rewrite", "map local":
			key := strings.ReplaceAll(section, " ", "_")
			var value any = line
			if key == "map_local" {
				var entry httpdebug.MapLocal
				encoded, _ := json.Marshal(line)
				err = json.Unmarshal(encoded, &entry)
				if err == nil && entry.DataType == "file" {
					var remote, data string
					remote, data, err = moduleResource(source, entry.Data)
					if err == nil {
						type plain httpdebug.MapLocal
						entry.Data = remote
						if remote == "" {
							entry.DataType = "base64"
							entry.Data = data
							entry.UpdateInterval = 0
						}
						value = plain(entry)
					}
				}
			}
			if err == nil {
				var check httpdebug.RewriteConfig
				encoded, _ := json.Marshal(moduleObject{key: []any{value}})
				err = json.Unmarshal(encoded, &check)
				if err == nil {
					result.values[key] = append(result.values[key], value)
				}
			}
		case "script":
			var kind string
			var entry moduleObject
			kind, entry, err = moduleScript(source, line)
			if err == nil {
				var check httpdebug.ScriptsConfig
				encoded, _ := json.Marshal(moduleObject{kind: []any{entry}})
				err = json.Unmarshal(encoded, &check)
				if err == nil {
					display.Kind = kind
					display.Index = len(result.values[kind])
					result.values[kind] = append(result.values[kind], entry)
				}
			}
		default:
			err = fmt.Errorf("unsupported section [%s]", section)
		}
		if err != nil {
			group = "ignored"
			display.Issue = err.Error()
		}
		result.Lines[group] = append(result.Lines[group], display)
	}
	result.resolvePanels(source.ID, panels)
	return result
}

var moduleHostname = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.?$`)

func DescribeSurgeModule(moduleJSON string) (string, error) {
	var source option.ModuleOptions
	if err := json.Unmarshal([]byte(moduleJSON), &source); err != nil {
		return "", err
	}
	data, err := json.Marshal(readModule(source))
	return string(data), err
}

func DescribeProfileSurgeModule(content, id string) (string, error) {
	stored, err := parseConfig(baseContext(nil), content)
	if err != nil {
		return "", err
	}
	offsets := map[string]int{"cron": 0, "event": 0, "generic": 0}
	if stored.Experimental != nil {
		if base := stored.Experimental.Scripts; base != nil {
			offsets["cron"] = len(base.Cron)
			offsets["event"] = len(base.Event)
			offsets["generic"] = len(base.Generic)
		}
		for _, source := range stored.Experimental.Modules {
			if source.ID != id && !source.Enabled {
				continue
			}
			parsed := readModule(source)
			if source.ID == id {
				for index, line := range parsed.Lines["script"] {
					parsed.Lines["script"][index].Index += offsets[line.Kind]
				}
				for index := range parsed.Panels {
					if parsed.Panels[index].Index >= 0 {
						parsed.Panels[index].Index += offsets["generic"]
					}
				}
				data, err := json.Marshal(parsed)
				return string(data), err
			}
			for kind := range offsets {
				offsets[kind] += len(parsed.values[kind])
			}
		}
	}
	return "", fmt.Errorf("module not found")
}

func effectiveModuleConfig(ctx context.Context, content string) (string, error) {
	return expandModuleConfig(ctx, content, nil)
}

func expandModuleConfig(ctx context.Context, content string, panels *[]modulePanel) (string, error) {
	if !strings.Contains(content, "modules") && !strings.Contains(content, `\u`) {
		return content, nil
	}
	stored, err := parseConfig(ctx, content)
	if err != nil {
		return "", err
	}
	if stored.Experimental == nil || len(stored.Experimental.Modules) == 0 {
		return content, nil
	}
	modules := stored.Experimental.Modules
	stored.Experimental.Modules = nil
	data, err := stored.MarshalJSONContext(ctx)
	if err != nil {
		return "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var root moduleObject
	if err = decoder.Decode(&root); err != nil {
		return "", err
	}
	object := func(parent moduleObject, key string) moduleObject {
		child, _ := parent[key].(map[string]any)
		if child == nil {
			child = moduleObject{}
			parent[key] = child
		}
		return child
	}
	experimental := object(root, "experimental")
	groups := map[string][]any{}
	var hosts moduleHostPatch
	types := uiConfigOutboundTypes(stored)
	direct := ""
	ids := map[string]bool{}
	genericOffset := 0
	if stored.Experimental.Scripts != nil {
		genericOffset = len(stored.Experimental.Scripts.Generic)
	}
	for _, source := range modules {
		if source.ID == "" || ids[source.ID] {
			return "", fmt.Errorf("each module must have a unique non-empty id")
		}
		ids[source.ID] = true
		if !source.Enabled {
			continue
		}
		parsed := readModule(source)
		if parsed.hosts.invalid != nil {
			return "", fmt.Errorf("module %q: %w", source.ID, parsed.hosts.invalid)
		}
		if hosts.replace == nil {
			hosts.insert = append(hosts.insert, parsed.hosts.insert...)
			hosts.append = append(hosts.append, parsed.hosts.append...)
			hosts.replace = parsed.hosts.replace
		}
		if panels != nil {
			for _, panel := range parsed.Panels {
				if panel.Index >= 0 {
					panel.Index += genericOffset
				}
				*panels = append(*panels, panel)
			}
			genericOffset += len(parsed.values["generic"])
		}
		for _, item := range parsed.values["rules"] {
			rule := item.(moduleObject)
			target, _ := rule["outbound"].(string)
			if strings.EqualFold(target, "DIRECT") {
				if direct == "" {
					direct = "module-direct"
					for number := 2; types[direct] != ""; number++ {
						direct = fmt.Sprintf("module-direct-%d", number)
					}
					list, _ := root["outbounds"].([]any)
					root["outbounds"] = append(list, moduleObject{"type": "direct", "tag": direct})
				}
				rule["outbound"] = direct
			} else if target != "" && types[target] == "" {
				return "", fmt.Errorf("module %q: unknown outbound %q", source.Name, target)
			}
		}
		for key, values := range parsed.values {
			groups[key] = append(groups[key], values...)
		}
	}
	for key, values := range groups {
		if len(values) == 0 {
			continue
		}
		var parent moduleObject
		last := false
		switch key {
		case "rules":
			parent = object(root, "route")
		case "dns":
			parent = object(root, "dns")
			key = "rules"
		case "http", "cron", "event", "generic":
			parent = object(experimental, "scripts")
			last = key != "http"
		default:
			parent = object(experimental, "http_rewrite")
		}
		existing, _ := parent[key].([]any)
		if last {
			parent[key] = append(existing, values...)
		} else {
			parent[key] = append(values, existing...)
		}
	}
	if hosts.replace != nil || len(hosts.insert)+len(hosts.append) > 0 {
		mitm := object(experimental, "mitm")
		combined := append([]string{}, hosts.insert...)
		if hosts.replace != nil {
			combined = append(combined, hosts.replace...)
		} else if stored.Experimental.MITM != nil {
			combined = append(combined, stored.Experimental.MITM.Hosts...)
		}
		mitm["hosts"] = append(combined, hosts.append...)
	}
	data, err = json.Marshal(root)
	return string(data), err
}
