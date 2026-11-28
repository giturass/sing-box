package rule

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"

	"go4.org/netipx"
)

func NewRuleSet(ctx context.Context, logger logger.ContextLogger, tag string, options option.RuleSet) (adapter.RuleSet, error) {
	switch options.Type {
	case C.RuleSetTypeInline, C.RuleSetTypeLocal, "":
		return NewLocalRuleSet(ctx, logger, tag, options)
	case C.RuleSetTypeRemote:
		return NewRemoteRuleSet(ctx, logger, tag, options)
	default:
		return nil, E.New("unknown rule-set type: ", options.Type)
	}
}

// Surge treats a resource's text format as part of its declaration, rather
// than guessing it from file extensions or interpreting it both ways.
func ValidateSurgeRuleSetResourceFormats(ctx context.Context, ruleSets []option.RuleSet) error {
	formats := map[string]string{}
	for _, options := range ruleSets {
		if options.Format != C.RuleSetFormatSurgeRules && options.Format != C.RuleSetFormatSurgeDomains {
			continue
		}
		for _, tag := range options.Tag {
			var identity string
			switch options.Type {
			case C.RuleSetTypeRemote:
				identity = "url:" + strings.ReplaceAll(options.RemoteOptions.URL, C.RuleSetTagPlaceholder, tag)
			case C.RuleSetTypeLocal:
				path := filemanager.BasePath(ctx, strings.ReplaceAll(options.LocalOptions.Path, C.RuleSetTagPlaceholder, tag))
				path, _ = filepath.Abs(path)
				identity = "path:" + path
			default:
				continue
			}
			if previous := formats[identity]; previous != "" && previous != options.Format {
				return E.New("one Surge rule-set resource cannot use both RULE-SET and DOMAIN-SET: ", identity)
			}
			formats[identity] = options.Format
		}
	}
	return nil
}

func extractIPSetFromRule(rawRule adapter.HeadlessRule) []*netipx.IPSet {
	switch rule := rawRule.(type) {
	case *DefaultHeadlessRule:
		return common.FlatMap(rule.destinationIPCIDRItems, func(rawItem RuleItem) []*netipx.IPSet {
			switch item := rawItem.(type) {
			case *IPCIDRItem:
				return []*netipx.IPSet{item.ipSet.IPSet()}
			case *SurgeIPCIDRItem:
				return []*netipx.IPSet{item.inner.ipSet.IPSet()}
			default:
				return nil
			}
		})
	case *LogicalHeadlessRule:
		return common.FlatMap(rule.rules, extractIPSetFromRule)
	default:
		panic("unexpected rule type")
	}
}

func HasHeadlessRule(rules []option.HeadlessRule, cond func(rule option.DefaultHeadlessRule) bool) bool {
	for _, rule := range rules {
		switch rule.Type {
		case C.RuleTypeDefault:
			if cond(rule.DefaultOptions) {
				return true
			}
		case C.RuleTypeLogical:
			if HasHeadlessRule(rule.LogicalOptions.Rules, cond) {
				return true
			}
		}
	}
	return false
}

func isProcessHeadlessRule(rule option.DefaultHeadlessRule) bool {
	return len(rule.ProcessName) > 0 || len(rule.ProcessPath) > 0 || len(rule.ProcessPathRegex) > 0 || len(rule.PackageName) > 0 || len(rule.PackageNameRegex) > 0
}

func isWIFIHeadlessRule(rule option.DefaultHeadlessRule) bool {
	return len(rule.WIFISSID) > 0 || len(rule.WIFIBSSID) > 0
}

func isIPCIDRHeadlessRule(rule option.DefaultHeadlessRule) bool {
	return len(rule.IPCIDR) > 0 || rule.IPSet != nil
}

func isDNSQueryTypeHeadlessRule(rule option.DefaultHeadlessRule) bool {
	return len(rule.QueryType) > 0
}

func isHTTPHeadlessRule(rule option.DefaultHeadlessRule) bool {
	return len(rule.HTTPURLRegex) > 0 || len(rule.HTTPUserAgent) > 0 || rule.Script != "" || rule.HTTPExtendedMatching || common.Any(rule.SurgeProtocol, func(value string) bool { return value == "HTTP" || value == "HTTPS" })
}

func isNonIPCIDRHeadlessRule(rule option.DefaultHeadlessRule) bool {
	ipOnly := option.DefaultHeadlessRule{
		IPCIDR:         rule.IPCIDR,
		IPSet:          rule.IPSet,
		Invert:         rule.Invert,
		SurgeIPCIDR:    rule.SurgeIPCIDR,
		SurgeNoResolve: rule.SurgeNoResolve,
	}
	return !reflect.DeepEqual(rule, ipOnly)
}

func buildRuleSetMetadata(headlessRules []option.HeadlessRule) adapter.RuleSetMetadata {
	return adapter.RuleSetMetadata{
		ContainsProcessRule:      HasHeadlessRule(headlessRules, isProcessHeadlessRule),
		ContainsWIFIRule:         HasHeadlessRule(headlessRules, isWIFIHeadlessRule),
		ContainsIPCIDRRule:       HasHeadlessRule(headlessRules, isIPCIDRHeadlessRule),
		ContainsDNSQueryTypeRule: HasHeadlessRule(headlessRules, isDNSQueryTypeHeadlessRule),
		ContainsHTTPRule:         HasHeadlessRule(headlessRules, isHTTPHeadlessRule),
		ContainsNonIPCIDRRule:    HasHeadlessRule(headlessRules, isNonIPCIDRHeadlessRule),
	}
}

func validateRuleSetMetadataUpdate(ctx context.Context, tag string, metadata adapter.RuleSetMetadata) error {
	validator := service.FromContext[adapter.DNSRuleSetUpdateValidator](ctx)
	if validator == nil {
		return nil
	}
	return validator.ValidateRuleSetMetadataUpdate(tag, metadata)
}
