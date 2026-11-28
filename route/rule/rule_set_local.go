package rule

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/fswatch"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service/filemanager"

	"go4.org/netipx"
)

var _ adapter.RuleSet = (*LocalRuleSet)(nil)

type LocalRuleSet struct {
	ctx          context.Context
	logger       logger.Logger
	tag          string
	content      atomic.Pointer[ruleSetContent]
	fileFormat   string
	deferredPath string
	watcher      *fswatch.Watcher
	access       sync.Mutex
	closed       bool
	started      bool
	inFlight     sync.WaitGroup
	callbacks    list.List[adapter.RuleSetUpdateCallback]
	refs         atomic.Int32
}

func NewLocalRuleSet(ctx context.Context, logger logger.Logger, tag string, options option.RuleSet) (*LocalRuleSet, error) {
	ruleSet := &LocalRuleSet{
		ctx:        ctx,
		logger:     logger,
		tag:        tag,
		fileFormat: options.Format,
	}
	if options.Type == C.RuleSetTypeInline {
		if len(options.InlineOptions.Rules) == 0 {
			return nil, E.New("empty inline rule-set")
		}
		err := ruleSet.reloadRules(options.InlineOptions.Rules)
		if err != nil {
			return nil, err
		}
	} else {
		filePath := filemanager.BasePath(ctx, strings.ReplaceAll(options.LocalOptions.Path, C.RuleSetTagPlaceholder, tag))
		filePath, _ = filepath.Abs(filePath)
		if options.Format == C.RuleSetFormatSurgeRules || options.Format == C.RuleSetFormatSurgeDomains {
			// Profile checking constructs the rule-set but never opens its Surge
			// resource. Loading belongs to the started service's lifecycle.
			ruleSet.deferredPath = filePath
			ruleSet.content.Store(&ruleSetContent{})
			return ruleSet, nil
		}
		err := ruleSet.reloadFile(filePath)
		if err != nil {
			return nil, err
		}
		watcher, err := fswatch.NewWatcher(fswatch.Options{
			Path: []string{filePath},
			Callback: func(path string) {
				uErr := ruleSet.reloadFile(path)
				if uErr != nil {
					logger.Error(E.Cause(uErr, "reload rule-set ", tag))
				}
			},
		})
		if err != nil {
			return nil, err
		}
		ruleSet.watcher = watcher
	}
	return ruleSet, nil
}

func (s *LocalRuleSet) Name() string {
	return s.tag
}

func (s *LocalRuleSet) String() string {
	return s.content.Load().String()
}

func (s *LocalRuleSet) StartContext(ctx context.Context, startContext *adapter.HTTPStartContext) error {
	done, err := s.admit()
	if err != nil {
		return err
	}
	defer done()
	s.access.Lock()
	if s.started {
		s.access.Unlock()
		return nil
	}
	deferredPath := s.deferredPath
	s.access.Unlock()
	var candidate *fswatch.Watcher
	if deferredPath != "" {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.reloadFile(deferredPath); err != nil {
			return err
		}
		candidate, err = fswatch.NewWatcher(fswatch.Options{Path: []string{deferredPath}, Callback: func(path string) {
			if err := s.reloadFile(path); err != nil {
				s.logger.Error(E.Cause(err, "reload Surge rule-set ", s.tag))
			}
		}})
		if err != nil {
			return err
		}
	}
	s.access.Lock()
	if s.closed || ctx.Err() != nil {
		s.access.Unlock()
		_ = common.Close(common.PtrOrNil(candidate))
		if err := ctx.Err(); err != nil {
			return err
		}
		return context.Canceled
	}
	if s.started {
		s.access.Unlock()
		return common.Close(common.PtrOrNil(candidate))
	}
	if candidate != nil {
		s.watcher, s.deferredPath = candidate, ""
	}
	if s.watcher != nil {
		err = s.watcher.Start()
		if err != nil {
			s.logger.Error(E.Cause(err, "watch rule-set file"))
		}
	}
	s.started = true
	s.access.Unlock()
	return nil
}

func (s *LocalRuleSet) reloadFile(path string) error {
	done, err := s.admit()
	if err != nil {
		return err
	}
	defer done()
	var ruleSet option.PlainRuleSetCompat
	switch s.fileFormat {
	case C.RuleSetFormatSurgeRules, C.RuleSetFormatSurgeDomains:
		content, err := filemanager.ReadFile(s.ctx, path)
		if err != nil {
			return err
		}
		plain, warnings, err := option.ParseSurgeRuleSet(content, s.fileFormat)
		for _, warning := range warnings {
			s.logger.Warn("Surge rule-set ", s.tag, " line ", warning.Line, ": ", warning.Issue)
		}
		if err != nil {
			return err
		}
		return s.reloadRules(plain.Rules)
	case C.RuleSetFormatSource, "":
		content, err := filemanager.ReadFile(s.ctx, path)
		if err != nil {
			return err
		}
		ruleSet, err = json.UnmarshalExtended[option.PlainRuleSetCompat](content)
		if err != nil {
			return err
		}
	case C.RuleSetFormatBinary:
		setFile, err := filemanager.Open(s.ctx, path)
		if err != nil {
			return err
		}
		defer setFile.Close()
		ruleSet, err = srs.Read(setFile, false)
		if err != nil {
			return err
		}
	default:
		return E.New("unknown rule-set format: ", s.fileFormat)
	}
	ruleSet, err = mmapRuleSet(s.ctx, s.logger, s.tag, ruleSet)
	if err != nil {
		return err
	}
	plainRuleSet, err := ruleSet.Upgrade()
	if err != nil {
		return err
	}
	return s.reloadRules(plainRuleSet.Rules)
}

func (s *LocalRuleSet) reloadRules(headlessRules []option.HeadlessRule) error {
	rules := make([]adapter.HeadlessRule, len(headlessRules))
	var err error
	for i, ruleOptions := range headlessRules {
		rules[i], err = NewHeadlessRule(s.ctx, ruleOptions)
		if err != nil {
			return E.Cause(err, "parse rule_set.rules.[", i, "]")
		}
	}
	metadata := buildRuleSetMetadata(headlessRules)
	err = validateRuleSetMetadataUpdate(s.ctx, s.tag, metadata)
	if err != nil {
		return err
	}
	s.access.Lock()
	if s.closed {
		s.access.Unlock()
		return context.Canceled
	}
	s.content.Store(&ruleSetContent{rules: rules, metadata: metadata})
	callbacks := s.callbacks.Array()
	s.access.Unlock()
	for _, callback := range callbacks {
		callback(s)
	}
	return nil
}

func (s *LocalRuleSet) Metadata() adapter.RuleSetMetadata {
	return s.content.Load().metadata
}

func (s *LocalRuleSet) ExtractIPSet() []*netipx.IPSet {
	return common.FlatMap(s.content.Load().rules, extractIPSetFromRule)
}

func (s *LocalRuleSet) IncRef() {
	s.refs.Add(1)
}

func (s *LocalRuleSet) DecRef() {
	if s.refs.Add(-1) < 0 {
		panic("rule-set: negative refs")
	}
}

func (s *LocalRuleSet) Cleanup() {
	if s.refs.Load() == 0 {
		s.content.Store(&ruleSetContent{})
	}
}

func (s *LocalRuleSet) RegisterCallback(callback adapter.RuleSetUpdateCallback) *list.Element[adapter.RuleSetUpdateCallback] {
	s.access.Lock()
	defer s.access.Unlock()
	return s.callbacks.PushBack(callback)
}

func (s *LocalRuleSet) UnregisterCallback(element *list.Element[adapter.RuleSetUpdateCallback]) {
	s.access.Lock()
	defer s.access.Unlock()
	s.callbacks.Remove(element)
}

func (s *LocalRuleSet) Close() error {
	s.access.Lock()
	s.closed = true
	s.content.Store(&ruleSetContent{})
	watcher := s.watcher
	s.watcher = nil
	s.access.Unlock()
	err := common.Close(common.PtrOrNil(watcher))
	s.inFlight.Wait()
	return err
}

func (s *LocalRuleSet) admit() (func(), error) {
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed {
		return nil, context.Canceled
	}
	s.inFlight.Add(1)
	return s.inFlight.Done, nil
}

func (s *LocalRuleSet) Match(metadata *adapter.InboundContext) bool {
	return s.content.Load().Match(metadata)
}

func (s *LocalRuleSet) loadContent() *ruleSetContent {
	return s.content.Load()
}
