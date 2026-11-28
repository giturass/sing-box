package rule

import (
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

var _ RuleItem = (*RuleSetItem)(nil)

type RuleSetItem struct {
	router            adapter.Router
	tagList           []string
	setList           []adapter.RuleSet
	ipCidrMatchSource bool
	ipCidrAcceptEmpty bool
	closed            bool
}

func NewRuleSetItem(router adapter.Router, tagList []string, ipCIDRMatchSource bool, ipCidrAcceptEmpty bool) *RuleSetItem {
	return &RuleSetItem{
		router:            router,
		tagList:           tagList,
		ipCidrMatchSource: ipCIDRMatchSource,
		ipCidrAcceptEmpty: ipCidrAcceptEmpty,
	}
}

func (r *RuleSetItem) Start() error {
	_ = r.Close()
	setList := make([]adapter.RuleSet, 0, len(r.tagList))
	for _, tag := range r.tagList {
		ruleSet, loaded := r.router.RuleSet(tag)
		if !loaded {
			return E.New("rule-set not found: ", tag)
		}
		setList = append(setList, ruleSet)
	}
	for _, ruleSet := range setList {
		ruleSet.IncRef()
	}
	r.setList = setList
	r.closed = false
	return nil
}

func (r *RuleSetItem) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	for _, ruleSet := range r.setList {
		ruleSet.DecRef()
	}
	return nil
}

func (r *RuleSetItem) Match(metadata *adapter.InboundContext) bool {
	snapshot := snapshotRuleMatch(metadata)
	pendingHTTP := false
	for _, ruleSet := range r.setList {
		r.prepareNestedMatch(metadata)
		if ruleSet.Match(metadata) {
			snapshot.restore(metadata)
			metadata.RuleMatchPendingHTTP = false
			return true
		}
		pendingHTTP = pendingHTTP || metadata.RuleMatchPendingHTTP
		if metadata.RuleMatchError != nil {
			break
		}
	}
	snapshot.restore(metadata)
	metadata.RuleMatchPendingHTTP = pendingHTTP
	return false
}

func (r *RuleSetItem) matchWithOuterGroups(metadata *adapter.InboundContext, outerGroups ruleGroupMatch) bool {
	outerDone := outerGroups.done()
	var (
		matched        bool
		deferredGroups uint8
		pendingHTTP    bool
	)
	snapshot := snapshotRuleMatch(metadata)
	for _, ruleSet := range r.setList {
		r.prepareNestedMatch(metadata)
		var rule adapter.HeadlessRule = ruleSet
		if provider, isProvider := ruleSet.(ruleSetContentProvider); isProvider {
			content := provider.loadContent()
			branch := content.mergeableRule()
			if branch != nil {
				branchGroups, branchMatched := branch.evaluateForMerge(metadata)
				if branchMatched {
					merged := outerGroups.mergeWith(branchGroups)
					if merged.done() {
						branchDeferredGroups := metadata.DeferredIPCIDRMatchGroups &^ uint8(merged.satisfied)
						if branchDeferredGroups == 0 {
							snapshot.restore(metadata)
							metadata.DeferredIPCIDRMatchGroups &^= uint8(merged.satisfied)
							metadata.RuleMatchPendingHTTP = false
							return true
						}
						matched = true
						deferredGroups |= branchDeferredGroups
					}
				}
				pendingHTTP = pendingHTTP || metadata.RuleMatchPendingHTTP
				continue
			}
			rule = content
		}
		if outerDone && rule.Match(metadata) {
			if metadata.DeferredIPCIDRMatchGroups == 0 {
				snapshot.restore(metadata)
				metadata.RuleMatchPendingHTTP = false
				return true
			}
			matched = true
			deferredGroups |= metadata.DeferredIPCIDRMatchGroups
		}
		pendingHTTP = pendingHTTP || metadata.RuleMatchPendingHTTP
		if metadata.RuleMatchError != nil {
			break
		}
	}
	snapshot.restore(metadata)
	metadata.RuleMatchPendingHTTP = pendingHTTP && !matched
	if matched {
		metadata.DeferredIPCIDRMatchGroups |= deferredGroups
	}
	return matched
}

func (r *RuleSetItem) prepareNestedMatch(metadata *adapter.InboundContext) {
	metadata.ResetRuleMatchCache()
	metadata.IPCIDRMatchSource = r.ipCidrMatchSource
	metadata.IPCIDRAcceptEmpty = r.ipCidrAcceptEmpty
}

type ruleSetContentProvider interface {
	loadContent() *ruleSetContent
}

type ruleSetContent struct {
	rules    []adapter.HeadlessRule
	metadata adapter.RuleSetMetadata
}

func (c *ruleSetContent) mergeableRule() *DefaultHeadlessRule {
	if len(c.rules) != 1 {
		return nil
	}
	rule, isDefault := c.rules[0].(*DefaultHeadlessRule)
	if !isDefault || rule.invert || rule.ruleSetItem != nil {
		return nil
	}
	return rule
}

func (c *ruleSetContent) Match(metadata *adapter.InboundContext) bool {
	var (
		matched        bool
		deferredGroups uint8
		pendingHTTP    bool
	)
	snapshot := snapshotRuleMatch(metadata)
	for _, rule := range c.rules {
		metadata.ResetRuleMatchCache()
		if rule.Match(metadata) {
			if metadata.DeferredIPCIDRMatchGroups == 0 {
				snapshot.restore(metadata)
				metadata.RuleMatchPendingHTTP = false
				return true
			}
			matched = true
			deferredGroups |= metadata.DeferredIPCIDRMatchGroups
		}
		pendingHTTP = pendingHTTP || metadata.RuleMatchPendingHTTP
		if metadata.RuleMatchError != nil {
			break
		}
	}
	snapshot.restore(metadata)
	metadata.RuleMatchPendingHTTP = pendingHTTP && !matched
	if matched {
		metadata.DeferredIPCIDRMatchGroups |= deferredGroups
	}
	return matched
}

func (c *ruleSetContent) String() string {
	return strings.Join(F.MapToString(c.rules), " ")
}

func (r *RuleSetItem) ContainsDestinationIPCIDRRule() bool {
	if r.ipCidrMatchSource {
		return false
	}
	return common.Any(r.setList, func(ruleSet adapter.RuleSet) bool {
		return ruleSet.Metadata().ContainsIPCIDRRule
	})
}

func (r *RuleSetItem) String() string {
	if len(r.tagList) == 1 {
		return F.ToString("rule_set=", r.tagList[0])
	} else {
		return F.ToString("rule_set=[", strings.Join(r.tagList, " "), "]")
	}
}
