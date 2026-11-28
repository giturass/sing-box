package rule

import (
	"io"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	F "github.com/sagernet/sing/common/format"
)

type abstractDefaultRule struct {
	items                   []RuleItem
	sourceAddressItems      []RuleItem
	sourcePortItems         []RuleItem
	destinationAddressItems []RuleItem
	destinationIPCIDRItems  []RuleItem
	destinationPortItems    []RuleItem
	allItems                []RuleItem
	ruleSetItem             *RuleSetItem
	invert                  bool
	action                  adapter.RuleAction
	httpExtendedMatching    bool
	surgeNoResolve          bool
}

func (r *abstractDefaultRule) Type() string {
	return C.RuleTypeDefault
}

func (r *abstractDefaultRule) Start() error {
	for _, item := range r.allItems {
		if starter, isStarter := item.(interface {
			Start() error
		}); isStarter {
			err := starter.Start()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *abstractDefaultRule) Close() error {
	for _, item := range r.allItems {
		err := common.Close(item)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *abstractDefaultRule) Match(metadata *adapter.InboundContext) bool {
	defer r.applySurgeScope(metadata)()
	if len(r.allItems) == 0 {
		return true
	}
	matched := r.matchInner(metadata)
	if metadata.RuleMatchPendingHTTP || metadata.RuleMatchError != nil {
		return false
	}
	if r.invert {
		if !matched {
			metadata.DeferredIPCIDRMatchGroups = 0
			return true
		}
		return metadata.DeferredIPCIDRMatchGroups != 0
	}
	return matched
}

func (r *abstractDefaultRule) matchInner(metadata *adapter.InboundContext) bool {
	groups := r.evaluateGroups(metadata)
	for _, item := range r.items {
		if !item.Match(metadata) {
			return false
		}
	}
	if r.ruleSetItem != nil {
		return r.ruleSetItem.matchWithOuterGroups(metadata, groups)
	}
	return groups.done()
}

func (r *abstractDefaultRule) evaluateForMerge(metadata *adapter.InboundContext) (ruleGroupMatch, bool) {
	defer r.applySurgeScope(metadata)()
	groups := r.evaluateGroups(metadata)
	for _, item := range r.items {
		if !item.Match(metadata) {
			return ruleGroupMatch{}, false
		}
	}
	return groups, true
}

func (r *abstractDefaultRule) applySurgeScope(metadata *adapter.InboundContext) func() {
	extended, noResolve := metadata.HTTPExtendedMatching, metadata.SurgeNoResolve
	metadata.HTTPExtendedMatching = extended || r.httpExtendedMatching
	metadata.SurgeNoResolve = noResolve || r.surgeNoResolve
	return func() { metadata.HTTPExtendedMatching, metadata.SurgeNoResolve = extended, noResolve }
}

func (r *abstractDefaultRule) destinationIPCIDRMatchesSource(metadata *adapter.InboundContext) bool {
	return metadata.IPCIDRMatchSource && len(r.destinationIPCIDRItems) > 0
}

func (r *abstractDefaultRule) destinationIPCIDRMatchesDestination(metadata *adapter.InboundContext) bool {
	return !metadata.IgnoreDestinationIPCIDRMatch && !metadata.IPCIDRMatchSource && len(r.destinationIPCIDRItems) > 0
}

func (r *abstractDefaultRule) evaluateGroups(metadata *adapter.InboundContext) ruleGroupMatch {
	var groups ruleGroupMatch
	if len(r.sourceAddressItems) > 0 {
		groups.required |= ruleMatchSourceAddress
		if matchAnyItem(r.sourceAddressItems, metadata) {
			groups.satisfied |= ruleMatchSourceAddress
		}
	}
	if r.destinationIPCIDRMatchesSource(metadata) {
		groups.required |= ruleMatchSourceAddress
		if !groups.satisfied.has(ruleMatchSourceAddress) && matchAnyItem(r.destinationIPCIDRItems, metadata) {
			groups.satisfied |= ruleMatchSourceAddress
		}
	}
	if len(r.sourcePortItems) > 0 {
		groups.required |= ruleMatchSourcePort
		if matchAnyItem(r.sourcePortItems, metadata) {
			groups.satisfied |= ruleMatchSourcePort
		}
	}
	destinationPendingHTTP := metadata.RuleMatchPendingHTTP
	if len(r.destinationAddressItems) > 0 {
		groups.required |= ruleMatchDestinationAddress
		if matchAnyItem(r.destinationAddressItems, metadata) {
			groups.satisfied |= ruleMatchDestinationAddress
		}
	}
	if r.destinationIPCIDRMatchesDestination(metadata) {
		groups.required |= ruleMatchDestinationAddress
		if !groups.satisfied.has(ruleMatchDestinationAddress) && matchAnyItem(r.destinationIPCIDRItems, metadata) {
			groups.satisfied |= ruleMatchDestinationAddress
			metadata.RuleMatchPendingHTTP = destinationPendingHTTP
		}
	}
	if len(r.destinationPortItems) > 0 {
		groups.required |= ruleMatchDestinationPort
		if matchAnyItem(r.destinationPortItems, metadata) {
			groups.satisfied |= ruleMatchDestinationPort
		}
	}
	if metadata.IgnoreDestinationIPCIDRMatch && !metadata.IPCIDRMatchSource && len(r.destinationIPCIDRItems) > 0 && len(r.destinationAddressItems) == 0 {
		metadata.DeferredIPCIDRMatchGroups |= uint8(ruleMatchDestinationAddress)
	}
	return groups
}

func (r *abstractDefaultRule) Action() adapter.RuleAction {
	return r.action
}

func (r *abstractDefaultRule) String() string {
	if !r.invert {
		return strings.Join(F.MapToString(r.allItems), " ")
	} else {
		return "!(" + strings.Join(F.MapToString(r.allItems), " ") + ")"
	}
}

type abstractLogicalRule struct {
	rules  []adapter.HeadlessRule
	mode   string
	invert bool
	action adapter.RuleAction
}

func (r *abstractLogicalRule) Type() string {
	return C.RuleTypeLogical
}

func (r *abstractLogicalRule) Start() error {
	for _, rule := range common.FilterIsInstance(r.rules, func(it adapter.HeadlessRule) (interface {
		Start() error
	}, bool,
	) {
		rule, loaded := it.(interface {
			Start() error
		})
		return rule, loaded
	}) {
		err := rule.Start()
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *abstractLogicalRule) Close() error {
	for _, rule := range common.FilterIsInstance(r.rules, func(it adapter.HeadlessRule) (io.Closer, bool) {
		rule, loaded := it.(io.Closer)
		return rule, loaded
	}) {
		err := rule.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *abstractLogicalRule) Match(metadata *adapter.InboundContext) bool {
	var (
		matched        bool
		deferredGroups uint8
		pendingHTTP    bool
	)
	snapshot := snapshotRuleMatch(metadata)
	if r.mode == C.LogicalTypeAnd {
		matched = true
		for _, rule := range r.rules {
			metadata.ResetRuleCache()
			childMatched := rule.Match(metadata)
			if metadata.RuleMatchError != nil {
				break
			}
			if metadata.RuleMatchPendingHTTP {
				pendingHTTP = true
				continue
			}
			if !childMatched {
				matched = false
				pendingHTTP = false
				deferredGroups = 0
				break
			}
			deferredGroups |= metadata.DeferredIPCIDRMatchGroups
		}
	} else {
		for _, rule := range r.rules {
			metadata.ResetRuleCache()
			childMatched := rule.Match(metadata)
			if metadata.RuleMatchError != nil {
				break
			}
			if metadata.RuleMatchPendingHTTP {
				pendingHTTP = true
				continue
			}
			if childMatched {
				matched = true
				pendingHTTP = false
				if metadata.DeferredIPCIDRMatchGroups == 0 {
					deferredGroups = 0
					break
				}
				deferredGroups |= metadata.DeferredIPCIDRMatchGroups
			}
		}
	}
	snapshot.restore(metadata)
	metadata.RuleMatchPendingHTTP = pendingHTTP
	if pendingHTTP || metadata.RuleMatchError != nil {
		return false
	}
	if matched {
		metadata.DeferredIPCIDRMatchGroups |= deferredGroups
	}
	if r.invert {
		if !matched {
			return true
		}
		return deferredGroups != 0
	}
	return matched
}

func (r *abstractLogicalRule) Action() adapter.RuleAction {
	return r.action
}

func (r *abstractLogicalRule) String() string {
	var op string
	switch r.mode {
	case C.LogicalTypeAnd:
		op = "&&"
	case C.LogicalTypeOr:
		op = "||"
	}
	if !r.invert {
		return strings.Join(F.MapToString(r.rules), " "+op+" ")
	} else {
		return "!(" + strings.Join(F.MapToString(r.rules), " "+op+" ") + ")"
	}
}

func matchAnyItem(items []RuleItem, metadata *adapter.InboundContext) bool {
	previousPending := metadata.RuleMatchPendingHTTP
	pending := false
	for _, item := range items {
		metadata.RuleMatchPendingHTTP = false
		if item.Match(metadata) {
			metadata.RuleMatchPendingHTTP = previousPending
			return true
		}
		pending = pending || metadata.RuleMatchPendingHTTP
		if metadata.RuleMatchError != nil {
			break
		}
	}
	metadata.RuleMatchPendingHTTP = previousPending || pending
	return false
}

func (s ruleMatchState) has(target ruleMatchState) bool {
	return s&target != 0
}
