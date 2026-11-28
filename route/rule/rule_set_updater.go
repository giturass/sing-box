package rule

import (
	"context"
	"runtime"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

type RuleSetUpdater struct {
	ctx      context.Context
	cancel   context.CancelFunc
	ruleSets []*RemoteRuleSet
	access   sync.Mutex
	started  bool
	closed   bool
	wg       sync.WaitGroup
}

func NewRuleSetUpdater(ctx context.Context, ruleSets []adapter.RuleSet) *RuleSetUpdater {
	var remoteRuleSets []*RemoteRuleSet
	for _, ruleSet := range ruleSets {
		remoteRuleSet, isRemote := ruleSet.(*RemoteRuleSet)
		if isRemote && !remoteRuleSet.updatesDisabled {
			remoteRuleSets = append(remoteRuleSets, remoteRuleSet)
		}
	}
	if len(remoteRuleSets) == 0 {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	return &RuleSetUpdater{
		ctx:      ctx,
		cancel:   cancel,
		ruleSets: remoteRuleSets,
	}
}

func (u *RuleSetUpdater) Start() {
	u.access.Lock()
	defer u.access.Unlock()
	if u.started || u.closed {
		return
	}
	u.started = true
	for _, ruleSet := range u.ruleSets {
		u.wg.Add(1)
		go func(ruleSet *RemoteRuleSet) { defer u.wg.Done(); u.loopUpdate(ruleSet) }(ruleSet)
	}
}

func (u *RuleSetUpdater) Close() error {
	u.access.Lock()
	u.closed = true
	u.cancel()
	u.access.Unlock()
	u.wg.Wait()
	return nil
}

func (u *RuleSetUpdater) loopUpdate(ruleSet *RemoteRuleSet) {
	ruleSet.access.Lock()
	nextUpdate := ruleSet.lastUpdated.Add(ruleSet.updateInterval)
	ruleSet.access.Unlock()
	wait := time.Until(nextUpdate)
	if wait < 0 {
		wait = 0
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		select {
		case <-u.ctx.Done():
			return
		case <-timer.C:
		}
		ruleSet.updateOnce(u.ctx)
		if u.ctx.Err() != nil {
			return
		}
		runtime.GC()
		timer.Reset(ruleSet.updateInterval)
	}
}

func waitUntilNext(nextUpdates []time.Time) time.Duration {
	next := nextUpdates[0]
	for _, nextUpdate := range nextUpdates[1:] {
		if nextUpdate.Before(next) {
			next = nextUpdate
		}
	}
	wait := time.Until(next)
	if wait < 0 {
		return 0
	}
	return wait
}
