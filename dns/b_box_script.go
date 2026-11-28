package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/httpdebug"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

// DNS Host processing belongs to one router lifetime. Keep its calls admitted
// until their transports have stopped, so the box can drain them before
// tearing down the selected outbound during a service reload.
type bBoxScriptDNSState struct {
	ctx    context.Context
	cancel context.CancelFunc
	access sync.Mutex
	closed bool
	calls  sync.WaitGroup

	match   func(context.Context, string) bool
	resolve func(context.Context, string, ...bool) (httpdebug.DNSScriptResult, bool, error)
}

func newBBoxScriptDNSState(parent context.Context) *bBoxScriptDNSState {
	ctx, cancel := context.WithCancel(parent)
	return &bBoxScriptDNSState{
		ctx: ctx, cancel: cancel,
		match:   httpdebug.DNSHostMatched,
		resolve: httpdebug.ResolveScriptDNS,
	}
}

func (r *Router) bBoxScriptDNSState() *bBoxScriptDNSState {
	r.rulesAccess.Lock()
	defer r.rulesAccess.Unlock()
	if r.bBoxScriptDNS == nil {
		r.bBoxScriptDNS = newBBoxScriptDNSState(r.ctx)
	}
	return r.bBoxScriptDNS
}

func (s *bBoxScriptDNSState) begin(parent context.Context) (context.Context, func(), error) {
	s.access.Lock()
	defer s.access.Unlock()
	if err := parent.Err(); err != nil {
		return nil, nil, err
	}
	if s.closed || s.ctx.Err() != nil {
		return nil, nil, errors.New("DNS Host processing closed")
	}
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(s.ctx, cancel)
	s.calls.Add(1)
	return ctx, sync.OnceFunc(func() {
		stop()
		cancel()
		s.calls.Done()
	}), nil
}

func (s *bBoxScriptDNSState) close() error {
	s.access.Lock()
	s.closed = true
	s.cancel()
	s.access.Unlock()
	s.calls.Wait()
	return nil
}

// StopScriptDNS rejects new Host evaluations and waits for selected DNS
// transports to stop. The box invokes it before closing outbound lifetimes;
// the router's own scope cleanup also calls close, making both paths idempotent.
func (r *Router) StopScriptDNS() error {
	return r.bBoxScriptDNSState().close()
}

func (r *Router) hasBBoxDNSHost(ctx context.Context, domain string) bool {
	return r.bBoxScriptDNSState().match(ctx, FqdnToDomain(domain))
}

func (r *Router) resolveBBoxDNSHost(ctx context.Context, domain string, options adapter.DNSQueryOptions) (httpdebug.DNSScriptResult, bool, error) {
	disableCache := options.DisableCache
	if client, loaded := r.client.(*Client); loaded {
		disableCache = disableCache || client.disableCache
	}
	return r.bBoxScriptDNSState().resolve(ctx, FqdnToDomain(domain), disableCache)
}

func (r *Router) exchangeBBoxDNSHost(ctx context.Context, message *mDNS.Msg, options adapter.DNSQueryOptions) (*mDNS.Msg, bool, error) {
	if !r.hasBBoxDNSHost(ctx, message.Question[0].Name) {
		return nil, false, nil
	}
	ctx, finish, err := r.bBoxScriptDNSState().begin(ctx)
	if err != nil {
		return nil, true, err
	}
	defer finish()
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}
	result, matched, err := r.resolveBBoxDNSHost(ctx, message.Question[0].Name, options)
	if err != nil {
		return nil, true, err
	}
	if !matched || result.Fallback {
		return nil, false, nil
	}
	if err = ctx.Err(); err != nil {
		return nil, true, err
	}
	if len(result.Servers) > 0 {
		response, exchangeErr := r.exchangeBBoxDNSServers(ctx, message, result.Servers, options)
		return response, true, exchangeErr
	}
	if result.Addresses == nil {
		return nil, true, errors.New("DNS script returned neither addresses nor servers")
	}
	response, err := bBoxDNSAddressResponse(message, result, r.finalizeExchangeOptions(options))
	return response, true, err
}

func (r *Router) lookupBBoxDNSHost(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, bool, error) {
	if !r.hasBBoxDNSHost(ctx, domain) {
		return nil, false, nil
	}
	ctx, finish, err := r.bBoxScriptDNSState().begin(ctx)
	if err != nil {
		return nil, true, err
	}
	defer finish()
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}
	result, matched, err := r.resolveBBoxDNSHost(ctx, domain, options)
	if err != nil {
		return nil, true, err
	}
	if !matched || result.Fallback {
		return nil, false, nil
	}
	if err = ctx.Err(); err != nil {
		return nil, true, err
	}
	if len(result.Servers) > 0 {
		addresses, lookupErr := r.lookupBBoxDNSServers(ctx, domain, result.Servers, options)
		return addresses, true, lookupErr
	}
	if result.Addresses == nil {
		return nil, true, errors.New("DNS script returned neither addresses nor servers")
	}
	addresses, err := bBoxDNSAddressesForStrategy(result.Addresses, r.resolveLookupStrategy(options))
	return addresses, true, err
}

func bBoxDNSAddressesForStrategy(addresses []netip.Addr, strategy C.DomainStrategy) ([]netip.Addr, error) {
	var addresses4, addresses6 []netip.Addr
	for _, address := range addresses {
		if !address.IsValid() || address.Zone() != "" {
			return nil, errors.New("DNS script returned an invalid IP address")
		}
		address = address.Unmap()
		if address.Is4() {
			addresses4 = append(addresses4, address)
		} else {
			addresses6 = append(addresses6, address)
		}
	}
	switch strategy {
	case C.DomainStrategyIPv4Only:
		return addresses4, nil
	case C.DomainStrategyIPv6Only:
		return addresses6, nil
	default:
		return sortAddresses(addresses4, addresses6, strategy), nil
	}
}

// An address resolver can synthesize only Internet-class A/AAAA records.
// ANY returns both families; other types/classes receive authoritative NODATA
// instead of borrowing unrelated records from the normal DNS configuration.
func bBoxDNSAddressResponse(message *mDNS.Msg, result httpdebug.DNSScriptResult, options adapter.DNSQueryOptions) (*mDNS.Msg, error) {
	addresses, err := bBoxDNSAddressesForStrategy(result.Addresses, options.Strategy)
	if err != nil {
		return nil, err
	}
	response := new(mDNS.Msg).SetReply(message)
	response.Authoritative = true
	response.RecursionAvailable = true
	// Script-generated records have no DNSSEC signatures. Do not echo AD as a
	// claim that the local result was authenticated.
	response.AuthenticatedData = false
	if edns := message.IsEdns0(); edns != nil {
		response.SetEdns0(edns.UDPSize(), edns.Do())
	}
	question := message.Question[0]
	if question.Qclass != mDNS.ClassINET || message.Opcode != mDNS.OpcodeQuery {
		return response, nil
	}
	ttl := uint32(0)
	if result.TTLSet {
		ttl = result.TTL
	}
	if options.RewriteTTL != nil {
		ttl = *options.RewriteTTL
	}
	for _, address := range addresses {
		header := mDNS.RR_Header{Name: question.Name, Class: question.Qclass, Ttl: ttl}
		if address.Is4() && (question.Qtype == mDNS.TypeA || question.Qtype == mDNS.TypeANY) {
			header.Rrtype = mDNS.TypeA
			response.Answer = append(response.Answer, &mDNS.A{Hdr: header, A: address.AsSlice()})
		} else if address.Is6() && (question.Qtype == mDNS.TypeAAAA || question.Qtype == mDNS.TypeANY) {
			header.Rrtype = mDNS.TypeAAAA
			response.Answer = append(response.Answer, &mDNS.AAAA{Hdr: header, AAAA: address.AsSlice()})
		}
	}
	return response, nil
}

func (r *Router) newBBoxDNSServer(ctx context.Context, server netip.Addr) (adapter.DNSTransport, *adapter.Scope, error) {
	if !server.IsValid() || server.Zone() != "" {
		return nil, nil, errors.New("DNS script returned an invalid DNS server IP")
	}
	if r.outbound == nil {
		return nil, nil, errors.New("DNS script server requires a named default outbound")
	}
	defaultOutbound := r.outbound.Default()
	if defaultOutbound == nil || defaultOutbound.Tag() == "" {
		return nil, nil, errors.New("DNS script server requires a named default outbound")
	}
	registry := service.FromContext[adapter.DNSTransportRegistry](r.ctx)
	if registry == nil {
		return nil, nil, errors.New("DNS transport registry unavailable for script server")
	}
	options := option.RemoteDNSServerOptions{
		RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{
			DialerOptions: option.DialerOptions{Detour: defaultOutbound.Tag()},
		},
		DNSServerAddressOptions: option.DNSServerAddressOptions{Server: server.Unmap().String(), ServerPort: 53},
	}
	// A returned server is an IP address, not a transport/outbound tag. The
	// registered UDP implementation preserves core interface/VPN handling and
	// retries truncated UDP replies over TCP through this same outbound.
	// ContextWith updates a registry in place. Clone it before installing the
	// temporary outbound view, leaving the running box's services untouched.
	transportCtx := httpdebug.WithoutScriptEvaluation(httpdebug.WithoutProcessing(service.ExtendContext(r.ctx)))
	transportCtx = service.ContextWith[adapter.OutboundManager](transportCtx, &bBoxDNSOutboundManager{
		OutboundManager: r.outbound, defaultOutbound: defaultOutbound, lifetime: ctx,
	})
	transport, err := registry.CreateDNSTransport(transportCtx, r.logger, "b-box-script-dns/"+server.String(), C.DNSTypeUDP, &options)
	if err != nil {
		return nil, nil, err
	}
	scope := adapter.NewScope(ctx, r.logger)
	for _, stage := range adapter.ListStartStages {
		if err = scope.Start("script DNS server", transport, stage); err != nil {
			_ = scope.Close()
			return nil, nil, err
		}
	}
	return transport, scope, nil
}

func (r *Router) exchangeBBoxDNSServers(ctx context.Context, message *mDNS.Msg, servers []netip.Addr, options adapter.DNSQueryOptions) (*mDNS.Msg, error) {
	ctx, cancel := context.WithCancel(httpdebug.WithoutScriptEvaluation(httpdebug.WithoutProcessing(ctx)))
	defer cancel()
	type serverResult struct {
		response *mDNS.Msg
		err      error
	}
	results := make(chan serverResult, len(servers))
	var calls sync.WaitGroup
	defer func() {
		cancel()
		calls.Wait()
	}()
	// A dynamic server choice is never persisted in the native DNS cache. Only
	// explicit address results with ttl are cached by the processing runtime.
	options.DisableCache = true
	options = r.finalizeExchangeOptions(options)
	for _, server := range servers {
		calls.Add(1)
		go func() {
			defer calls.Done()
			transport, scope, err := r.newBBoxDNSServer(ctx, server)
			if err != nil {
				results <- serverResult{err: err}
				return
			}
			defer scope.Close()
			response, err := r.client.Exchange(adapter.OverrideContext(ctx), transport, message.Copy(), options, nil)
			if ctx.Err() != nil {
				response, err = nil, ctx.Err()
			}
			if err == nil && response == nil {
				err = errors.New("DNS server returned an empty response")
			}
			if response != nil {
				response.Id = message.Id
				response.Question = slices.Clone(message.Question)
			}
			results <- serverResult{response: response, err: err}
		}()
	}
	var fallbackResponse *mDNS.Msg
	var serverErrors []error
	for range servers {
		select {
		case result := <-results:
			if result.err != nil {
				serverErrors = append(serverErrors, result.err)
				continue
			}
			if result.response.Rcode == mDNS.RcodeSuccess {
				return result.response, nil
			}
			if fallbackResponse == nil {
				fallbackResponse = result.response
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if fallbackResponse != nil {
		return fallbackResponse, nil
	}
	return nil, fmt.Errorf("script DNS servers failed: %w", errors.Join(serverErrors...))
}

func (r *Router) lookupBBoxDNSServers(ctx context.Context, domain string, servers []netip.Addr, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	strategy := r.resolveLookupStrategy(options)
	// Match native Lookup precedence: an explicit lookup strategy controls the
	// exchange strategy too, so a conflicting default cannot reject its query.
	if strategy != C.DomainStrategyAsIS {
		options.Strategy = strategy
	}
	queryTypes := []uint16{mDNS.TypeA, mDNS.TypeAAAA}
	if strategy == C.DomainStrategyIPv4Only {
		queryTypes = queryTypes[:1]
	} else if strategy == C.DomainStrategyIPv6Only {
		queryTypes = queryTypes[1:]
	}
	type lookupResult struct {
		addresses []netip.Addr
		err       error
	}
	results := make(chan lookupResult, len(queryTypes))
	var calls sync.WaitGroup
	defer calls.Wait()
	for _, queryType := range queryTypes {
		calls.Add(1)
		go func() {
			defer calls.Done()
			request := new(mDNS.Msg).SetQuestion(mDNS.Fqdn(domain), queryType)
			response, err := r.exchangeBBoxDNSServers(withLookupQueryMetadata(ctx, queryType), request, servers, options)
			if err == nil && response.Rcode != mDNS.RcodeSuccess {
				err = RcodeError(response.Rcode)
			}
			var addresses []netip.Addr
			if err == nil {
				addresses = filterAddressesByQueryType(MessageToAddresses(response), queryType)
			}
			results <- lookupResult{addresses, err}
		}()
	}
	var addresses []netip.Addr
	var lookupErrors []error
	for range queryTypes {
		result := <-results
		addresses = append(addresses, result.addresses...)
		if result.err != nil {
			lookupErrors = append(lookupErrors, result.err)
		}
	}
	if len(addresses) == 0 {
		return nil, errors.Join(lookupErrors...)
	}
	return bBoxDNSAddressesForStrategy(addresses, strategy)
}
