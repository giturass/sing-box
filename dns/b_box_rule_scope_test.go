package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type bBoxDNSRuleScopeContextKey struct{}

type bBoxDNSRuleScopeRecorder struct {
	adapter.DNSRule
	access    sync.Mutex
	snapshots []adapter.InboundContext
}

func (r *bBoxDNSRuleScopeRecorder) record(metadata *adapter.InboundContext) {
	r.access.Lock()
	r.snapshots = append(r.snapshots, *metadata)
	r.access.Unlock()
}

func (r *bBoxDNSRuleScopeRecorder) Match(metadata *adapter.InboundContext) bool {
	r.record(metadata)
	return r.DNSRule.Match(metadata)
}

func (r *bBoxDNSRuleScopeRecorder) LegacyPreMatch(metadata *adapter.InboundContext) bool {
	r.record(metadata)
	return r.DNSRule.LegacyPreMatch(metadata)
}

func TestBBoxDNSRuleEntrypointsOwnContextAndDiscardInheritedRouteState(t *testing.T) {
	t.Parallel()
	for _, legacy := range []bool{false, true} {
		for _, api := range []string{"Lookup", "Exchange", "ExchangeAsync"} {
			t.Run(fmt.Sprintf("legacy=%t/%s", legacy, api), func(t *testing.T) {
				transport := &fakeDNSTransport{tag: "final", immediate: true, address: netip.MustParseAddr("192.0.2.250")}
				router := raceTestRouter(t, transport)
				router.legacyDNSMode = legacy
				// Keep this metadata test independent of the process-wide script
				// engine, while exercising the real DNS routing entrypoints.
				state := newBBoxScriptDNSState(router.ctx)
				state.match = func(context.Context, string) bool { return false }
				router.bBoxScriptDNS = state
				t.Cleanup(func() { require.NoError(t, state.close()) })
				var options option.DNSRule
				require.NoError(t, json.Unmarshal([]byte(`{"domain":"scope.test","server":"final"}`), &options))
				dnsRule, err := R.NewDNSRule(context.Background(), log.NewNOPFactory().Logger(), options, true, legacy)
				require.NoError(t, err)
				require.NoError(t, dnsRule.Start())
				t.Cleanup(func() { require.NoError(t, dnsRule.Close()) })
				recorder := &bBoxDNSRuleScopeRecorder{DNSRule: dnsRule}
				router.rules = []adapter.DNSRule{recorder}
				caller, cancel := context.WithCancel(context.WithValue(context.Background(), bBoxDNSRuleScopeContextKey{}, "caller"))
				defer cancel()
				metadata := adapter.InboundContext{
					Inbound: "mixed", User: "owner", Network: "tcp", Protocol: "http",
					Source: M.ParseSocksaddr("192.0.2.2:12000"), Destination: M.ParseSocksaddr("old-route.test:443"), Domain: "old-route.test",
					ProcessInfo:      &adapter.ConnectionOwner{ProcessID: 17, UserId: 10001, PackageNames: []string{"io.test.owner"}},
					RuleMatchContext: context.Background(), RuleMatchError: errors.New("old route error"),
					RuleScriptResults: map[string]bool{"choose": true}, RuleMatchDNSResolved: true,
					RuleMatchNeedsResolution: true, RuleMatchNeedsHTTP: true, RuleMatchPendingHTTP: true,
					DestinationAddresses: []netip.Addr{netip.MustParseAddr("198.51.100.1")},
					HTTPURL:              "https://old-route.test/path", HTTPUserAgent: "old-agent", HTTPHost: "old-host.test", HTTPServerName: "old-sni.test",
					HTTPExtendedMatching: true, SurgeNoResolve: true,
				}
				original := metadata
				caller = adapter.WithContext(caller, &metadata)
				queryOptions := adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv4Only, LookupStrategy: C.DomainStrategyIPv4Only}
				query := new(mDNS.Msg).SetQuestion("scope.test.", mDNS.TypeA)
				switch api {
				case "Lookup":
					addresses, err := router.Lookup(caller, "scope.test", queryOptions)
					require.NoError(t, err)
					require.Equal(t, []netip.Addr{transport.address}, addresses)
				case "Exchange":
					response, err := router.Exchange(caller, query, queryOptions)
					require.NoError(t, err)
					require.Len(t, response.Answer, 1)
				case "ExchangeAsync":
					type result struct {
						response *mDNS.Msg
						err      error
					}
					completed := make(chan result, 1)
					router.ExchangeAsync(caller, query, queryOptions, func(response *mDNS.Msg, err error) { completed <- result{response, err} })
					select {
					case output := <-completed:
						require.NoError(t, output.err)
						require.Len(t, output.response.Answer, 1)
					case <-time.After(3 * time.Second):
						t.Fatal("asynchronous DNS query did not finish")
					}
				}
				recorder.access.Lock()
				snapshots := append([]adapter.InboundContext(nil), recorder.snapshots...)
				recorder.access.Unlock()
				require.NotEmpty(t, snapshots, "the DNS entrypoint bypassed its native rules")
				for _, snapshot := range snapshots {
					require.True(t, snapshot.DNSFlow)
					require.Equal(t, "scope.test", snapshot.Domain)
					require.NotNil(t, snapshot.RuleMatchContext)
					require.Equal(t, "caller", snapshot.RuleMatchContext.Value(bBoxDNSRuleScopeContextKey{}))
					require.NoError(t, snapshot.RuleMatchContext.Err())
					require.NoError(t, snapshot.RuleMatchError)
					require.Nil(t, snapshot.RuleScriptResults)
					require.False(t, snapshot.RuleMatchDNSResolved)
					require.False(t, snapshot.RuleMatchNeedsResolution)
					require.False(t, snapshot.RuleMatchNeedsHTTP)
					require.False(t, snapshot.RuleMatchPendingHTTP)
					require.Empty(t, snapshot.DestinationAddresses)
					require.Empty(t, snapshot.HTTPURL)
					require.Empty(t, snapshot.HTTPUserAgent)
					require.Empty(t, snapshot.HTTPHost)
					require.Empty(t, snapshot.HTTPServerName)
					require.False(t, snapshot.HTTPExtendedMatching)
					require.False(t, snapshot.SurgeNoResolve)
					require.Equal(t, original.Source, snapshot.Source)
					require.Equal(t, original.Inbound, snapshot.Inbound)
					require.Equal(t, original.User, snapshot.User)
					require.Same(t, original.ProcessInfo, snapshot.ProcessInfo)
				}
				require.Equal(t, original, metadata, "DNS evaluation mutated its parent route request")
				cancel()
				for _, snapshot := range snapshots {
					require.ErrorIs(t, snapshot.RuleMatchContext.Err(), context.Canceled, "DNS matching inherited a background route context")
				}
			})
		}
	}
}
