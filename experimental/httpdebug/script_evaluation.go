package httpdebug

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/dop251/goja"
)

// DNSHost preserves the order of Surge's [Host] entries. Static mappings do
// not depend on the scripting switch; only a script entry executes JavaScript.
type DNSHost struct {
	Pattern   string   `json:"pattern"`
	Script    string   `json:"script,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
}

type compiledDNSHost struct {
	pattern   string
	script    string
	addresses []netip.Addr
}

// The core installs the configured names in its instance context. A remote
// rule set can therefore validate SCRIPT references when it is loaded, before
// processing is activated, without consulting another profile's runtime.
type ScriptDeclarations struct {
	Rule map[string]bool
	DNS  map[string]bool
}

func ValidateDNSHosts(hosts []DNSHost) error {
	_, err := compileDNSHosts(hosts)
	return err
}

func NormalizeDNSHostPattern(value string) (string, error) {
	value = normalizeHost(strings.TrimSpace(value))
	if value == "" || !validHost(strings.NewReplacer("*", "a", "?", "a").Replace(value)) {
		return "", errors.New("expected a hostname, IP address or * / ? host pattern")
	}
	return value, nil
}

func compileDNSHosts(hosts []DNSHost) ([]compiledDNSHost, error) {
	compiled := make([]compiledDNSHost, 0, len(hosts))
	for i, host := range hosts {
		pattern, err := NormalizeDNSHostPattern(host.Pattern)
		if err != nil {
			return nil, fmt.Errorf("dns_hosts[%d]: %w", i, err)
		}
		if (host.Script == "") == (len(host.Addresses) == 0) {
			return nil, fmt.Errorf("dns_hosts[%d]: use exactly one of script or non-empty addresses", i)
		}
		item := compiledDNSHost{pattern: pattern, script: host.Script}
		for _, value := range host.Addresses {
			address, err := netip.ParseAddr(value)
			if err != nil || address.Zone() != "" {
				return nil, fmt.Errorf("dns_hosts[%d]: invalid IP address", i)
			}
			item.addresses = append(item.addresses, address.Unmap())
		}
		compiled = append(compiled, item)
	}
	return compiled, nil
}

// These fields are request observations, not connection-wide synthetic HTTP
// values. Unavailable Surge properties are represented as null in JavaScript.
type RuleScriptRequest struct {
	Hostname    string
	DestPort    uint16
	SourcePort  uint16
	Protocol    string
	ProcessPath string
	UserAgent   string
	URL         string
	SourceIP    string
	ListenPort  uint16
	Resolved    bool
	DNSResult   []netip.Addr
}

func (r RuleScriptRequest) value() map[string]any {
	stringValue := func(value string) any {
		if value == "" {
			return nil
		}
		return value
	}
	portValue := func(value uint16) any {
		if value == 0 {
			return nil
		}
		return int(value)
	}
	value := map[string]any{
		"hostname": stringValue(r.Hostname), "destPort": portValue(r.DestPort),
		"sourcePort": portValue(r.SourcePort), "protocol": stringValue(r.Protocol),
		"processPath": stringValue(r.ProcessPath), "userAgent": stringValue(r.UserAgent),
		"url": stringValue(r.URL), "sourceIP": stringValue(r.SourceIP),
		"listenPort": portValue(r.ListenPort), "dnsResult": nil,
	}
	if r.Resolved {
		v4, v6 := []string{}, []string{}
		for _, address := range r.DNSResult {
			if address.Is4() {
				v4 = append(v4, address.String())
			} else if address.Is6() {
				v6 = append(v6, address.String())
			}
		}
		value["dnsResult"] = map[string]any{"v4Addresses": v4, "v6Addresses": v6}
	}
	return value
}

// Rule/DNS scripts may issue routed requests, but cannot recursively evaluate
// themselves while fetching their source, resolving a server or using HTTP.
type scriptEvaluationContextKey struct{}

func WithoutScriptEvaluation(ctx context.Context) context.Context {
	return context.WithValue(ctx, scriptEvaluationContextKey{}, true)
}

func ScriptEvaluationDisabled(ctx context.Context) bool {
	return ctx != nil && ctx.Value(scriptEvaluationContextKey{}) != nil
}

func admitScriptEvaluation(e *Engine, parent context.Context) (context.Context, func(), bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.ctx.Err() != nil {
		return nil, nil, false
	}
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(e.ctx, cancel)
	e.wg.Add(1)
	return ctx, func() { cancel(); stop(); e.wg.Done() }, true
}

func runEvaluationScript(ctx context.Context, task compiledTask, environment scriptEnvironment, limit int64,
	setup func(*goja.Runtime), done func(context.Context, *goja.Runtime, goja.Value) error) (err error) {
	defer func() {
		if err != nil {
			writeLog("warn", task.label+": "+err.Error())
		}
	}()
	ctx, cancel := scriptContext(ctx, task.options.TimeoutMS)
	defer cancel()
	program := task.program
	if task.source != nil {
		if environment.resources == nil {
			return ErrScriptsInactive
		}
		value, lease, err := environment.resources.get(WithoutScriptEvaluation(ctx), task.source)
		if err != nil {
			return fmt.Errorf("%s: script loading: %w", task.label, err)
		}
		defer lease.release()
		program = value.program
	}
	cleanup := func() {}
	defer func() { cleanup() }()
	err = executeScript(ctx, program, task.label, task.key.kind, task.options.TimeoutMS, task.options.Argument, false,
		func(vm *goja.Runtime, invocation context.Context) {
			cleanup = installScriptHTTP(vm, WithoutScriptEvaluation(invocation), environment.dial, environment.roots, limit, task.client)
			key := task.storageKey
			if task.source != nil {
				key = "script." + environment.resources.key(task.source)
			}
			installScriptStorage(vm, invocation, environment.storage, task.options.StorageNamespace, task.label, key)
			setup(vm)
		}, func(vm *goja.Runtime, value goja.Value) error {
			if err := done(ctx, vm, value); err != nil {
				return err
			}
			return ctx.Err()
		}, scriptRunInfo{name: task.options.Name})
	if err == nil {
		err = ctx.Err()
	}
	return err
}

func MatchRuleScript(parent context.Context, name string, request RuleScriptRequest) (bool, error) {
	if ScriptEvaluationDisabled(parent) {
		return false, nil
	}
	e := active.Load()
	if e == nil || e.scripts == nil {
		return false, nil
	}
	task, found := e.scripts.rule[name]
	if !found {
		return false, nil
	}
	ctx, release, admitted := admitScriptEvaluation(e, parent)
	if !admitted {
		if err := parent.Err(); err != nil {
			return false, err
		}
		return false, context.Canceled
	}
	defer release()
	matched := false
	err := runEvaluationScript(ctx, task, e.scriptEnvironment, e.scripts.limit,
		func(vm *goja.Runtime) { _ = vm.Set("$request", request.value()) },
		func(ctx context.Context, _ *goja.Runtime, value goja.Value) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			object, ok := value.(*goja.Object)
			if !ok || len(object.Keys()) != 1 || object.Keys()[0] != "matched" {
				return errors.New("rule script must call $done({matched: boolean})")
			}
			field := object.Get("matched")
			if field.ExportType() != reflect.TypeFor[bool]() {
				return errors.New("matched must be a boolean")
			}
			matched = field.ToBoolean()
			return nil
		})
	if err != nil {
		return false, err
	}
	return matched, nil
}

type DNSScriptResult struct {
	Addresses []netip.Addr
	Servers   []netip.Addr
	TTL       uint32
	TTLSet    bool
	Fallback  bool
}

type dnsScriptCacheEntry struct {
	result  DNSScriptResult
	expires time.Time
}

func decodeDNSScriptResult(ctx context.Context, value goja.Value) (DNSScriptResult, error) {
	var result DNSScriptResult
	if err := ctx.Err(); err != nil {
		return result, err
	}
	object, ok := value.(*goja.Object)
	if !ok {
		return result, errors.New("DNS script must return an object")
	}
	keys := object.Keys()
	if len(keys) == 0 {
		result.Fallback = true
		return result, nil
	}
	selection := ""
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		switch key {
		case "address", "addresses", "server", "servers":
			if selection != "" {
				return result, errors.New("DNS script must return exactly one address, addresses, server or servers")
			}
			selection = key
		case "ttl":
		default:
			return result, fmt.Errorf("unsupported DNS script result field %q", key)
		}
	}
	if selection == "" {
		return result, errors.New("DNS script result requires address, addresses, server or servers")
	}
	field := object.Get(selection)
	parse := func(value goja.Value) (netip.Addr, error) {
		if value.ExportType() != reflect.TypeFor[string]() {
			return netip.Addr{}, errors.New("DNS script addresses and servers must be IP strings")
		}
		address, err := netip.ParseAddr(value.String())
		if err != nil || address.Zone() != "" {
			return netip.Addr{}, errors.New("DNS script addresses and servers must be IP addresses without a port or zone")
		}
		return address.Unmap(), nil
	}
	var addresses []netip.Addr
	if selection == "address" || selection == "server" {
		address, err := parse(field)
		if err != nil {
			return result, err
		}
		addresses = append(addresses, address)
	} else {
		array, ok := field.(*goja.Object)
		if !ok || array.ClassName() != "Array" {
			return result, errors.New("addresses and servers must be non-empty IP arrays")
		}
		length := array.Get("length").ToInteger()
		if length == 0 {
			return result, errors.New("addresses and servers must be non-empty IP arrays")
		}
		for i := int64(0); i < length; i++ {
			if err := ctx.Err(); err != nil {
				return result, err
			}
			address, err := parse(array.Get(fmt.Sprint(i)))
			if err != nil {
				return result, err
			}
			addresses = append(addresses, address)
		}
	}
	if selection == "server" || selection == "servers" {
		result.Servers = addresses
	} else {
		result.Addresses = addresses
	}
	if slices.Contains(keys, "ttl") {
		if len(result.Servers) > 0 {
			return result, errors.New("ttl is only supported for address results")
		}
		number := object.Get("ttl")
		if number.ExportType() != reflect.TypeFor[int64]() && number.ExportType() != reflect.TypeFor[float64]() {
			return result, errors.New("ttl must be an unsigned integer number of seconds")
		}
		seconds := number.ToFloat()
		if seconds < 0 || seconds > math.MaxUint32 || seconds != math.Trunc(seconds) {
			return result, errors.New("ttl must be an unsigned integer number of seconds")
		}
		result.TTL, result.TTLSet = uint32(seconds), true
	}
	if err := ctx.Err(); err != nil {
		return DNSScriptResult{}, err
	}
	return result, nil
}

func matchingDNSHost(e *Engine, domain string) *compiledDNSHost {
	domain = normalizeHost(domain)
	for i := range e.dnsHosts {
		if matchHostGlob(e.dnsHosts[i].pattern, domain) {
			return &e.dnsHosts[i]
		}
	}
	return nil
}

func DNSHostMatched(ctx context.Context, domain string) bool {
	e := active.Load()
	if e == nil {
		return false
	}
	host := matchingDNSHost(e, domain)
	return host != nil && (host.script == "" || !ScriptEvaluationDisabled(ctx))
}

func ClearScriptDNSCache() {
	if e := active.Load(); e != nil {
		e.mu.Lock()
		clear(e.dnsCache)
		e.mu.Unlock()
	}
}

func ResolveScriptDNS(parent context.Context, domain string, disableCache ...bool) (DNSScriptResult, bool, error) {
	e := active.Load()
	if e == nil {
		return DNSScriptResult{}, false, nil
	}
	host := matchingDNSHost(e, domain)
	if host == nil {
		return DNSScriptResult{}, false, nil
	}
	if host.script != "" && (ScriptEvaluationDisabled(parent) || e.scripts == nil) {
		return DNSScriptResult{}, false, nil
	}
	ctx, release, admitted := admitScriptEvaluation(e, parent)
	if !admitted {
		if err := parent.Err(); err != nil {
			return DNSScriptResult{}, true, err
		}
		return DNSScriptResult{}, true, context.Canceled
	}
	defer release()
	if err := ctx.Err(); err != nil {
		return DNSScriptResult{}, true, err
	}
	if host.script == "" {
		return DNSScriptResult{Addresses: slices.Clone(host.addresses), TTL: 60, TTLSet: true}, true, nil
	}
	task, found := e.scripts.dns[host.script]
	if !found {
		return DNSScriptResult{}, false, nil
	}
	cache := len(disableCache) == 0 || !disableCache[0]
	key := normalizeHost(domain)
	if cache {
		e.mu.Lock()
		entry, found := e.dnsCache[key]
		if found && time.Now().Before(entry.expires) {
			result := entry.result
			result.Addresses = slices.Clone(result.Addresses)
			result.TTL = uint32(max(0, int64(time.Until(entry.expires)/time.Second)))
			e.mu.Unlock()
			return result, true, nil
		}
		delete(e.dnsCache, key)
		e.mu.Unlock()
	}
	var result DNSScriptResult
	err := runEvaluationScript(ctx, task, e.scriptEnvironment, e.scripts.limit,
		func(vm *goja.Runtime) { _ = vm.Set("$domain", key) },
		func(ctx context.Context, _ *goja.Runtime, value goja.Value) error {
			var err error
			result, err = decodeDNSScriptResult(ctx, value)
			return err
		})
	if err != nil {
		return DNSScriptResult{}, true, err
	}
	if cache && result.TTLSet && result.TTL > 0 && len(result.Addresses) > 0 {
		e.mu.Lock()
		if !e.closed && ctx.Err() == nil {
			if e.dnsCache == nil {
				e.dnsCache = make(map[string]dnsScriptCacheEntry)
			}
			cached := result
			cached.Addresses = slices.Clone(result.Addresses)
			e.dnsCache[key] = dnsScriptCacheEntry{result: cached, expires: time.Now().Add(time.Duration(result.TTL) * time.Second)}
		}
		e.mu.Unlock()
	}
	if err := ctx.Err(); err != nil {
		return DNSScriptResult{}, true, err
	}
	return result, true, nil
}
