package rule

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/dlclark/regexp2/v2"
	"github.com/sagernet/sing-box/adapter"
)

// HTTP matchers only inspect a parsed request. A TLS/QUIC connection, DNS
// flow or pre-match packet cannot satisfy an inverted request condition either.
type HTTPURLRegexItem struct {
	patterns    []httpURLPattern
	description string
}

type httpURLPattern struct {
	linear       *regexp.Regexp
	backtracking *regexp2.Regexp
}

func NewHTTPURLRegexItem(patterns []string) (*HTTPURLRegexItem, error) {
	item := &HTTPURLRegexItem{description: "http_url_regex=" + strings.Join(patterns, "|")}
	for _, pattern := range patterns {
		if pattern == "" {
			return nil, fmt.Errorf("http_url_regex: empty expression")
		}
		if compiled, err := regexp.Compile(pattern); err == nil {
			item.patterns = append(item.patterns, httpURLPattern{linear: compiled})
			continue
		}
		compiled, err := regexp2.Compile(pattern, regexp2.RE2, regexp2.OptionMaintainCaptureOrder())
		if err != nil {
			return nil, fmt.Errorf("http_url_regex: %w", err)
		}
		if compiled.RightToLeft() {
			return nil, fmt.Errorf("http_url_regex: right-to-left mode is not supported")
		}
		item.patterns = append(item.patterns, httpURLPattern{backtracking: compiled})
	}
	return item, nil
}

func (r *HTTPURLRegexItem) Match(metadata *adapter.InboundContext) bool {
	if metadata.DNSFlow || metadata.HTTPURL == "" {
		metadata.RuleMatchPendingHTTP = true
		return false
	}
	ctx := metadata.RuleMatchContext
	if ctx == nil {
		ctx = context.Background()
	}
	for _, candidate := range HTTPRequestURLs(metadata) {
		for _, pattern := range r.patterns {
			if err := ctx.Err(); err != nil {
				metadata.RuleMatchError = err
				return false
			}
			if pattern.linear != nil {
				if pattern.linear.MatchString(candidate) {
					return true
				}
				continue
			}
			matched, err := pattern.backtracking.WithContext(ctx).MatchString(candidate)
			if err != nil {
				metadata.RuleMatchError = err
				return false
			}
			if matched {
				return true
			}
		}
	}
	return false
}

func (r *HTTPURLRegexItem) String() string { return r.description }

type HTTPUserAgentItem struct {
	patterns    []*regexp.Regexp
	description string
}

func NewHTTPUserAgentItem(patterns []string) (*HTTPUserAgentItem, error) {
	item := &HTTPUserAgentItem{description: "http_user_agent=" + strings.Join(patterns, "|")}
	for _, pattern := range patterns {
		var expression strings.Builder
		expression.WriteString("(?s)^")
		for _, character := range pattern {
			switch character {
			case '*':
				expression.WriteString(".*")
			case '?':
				expression.WriteByte('.')
			default:
				expression.WriteString(regexp.QuoteMeta(string(character)))
			}
		}
		expression.WriteByte('$')
		compiled, err := regexp.Compile(expression.String())
		if err != nil {
			return nil, err
		}
		item.patterns = append(item.patterns, compiled)
	}
	return item, nil
}

func (r *HTTPUserAgentItem) Match(metadata *adapter.InboundContext) bool {
	if metadata.DNSFlow || metadata.HTTPURL == "" {
		metadata.RuleMatchPendingHTTP = true
		return false
	}
	if ctx := metadata.RuleMatchContext; ctx != nil && ctx.Err() != nil {
		metadata.RuleMatchError = ctx.Err()
		return false
	}
	for _, pattern := range r.patterns {
		if pattern.MatchString(metadata.HTTPUserAgent) {
			return true
		}
	}
	return false
}

func (r *HTTPUserAgentItem) String() string { return r.description }
