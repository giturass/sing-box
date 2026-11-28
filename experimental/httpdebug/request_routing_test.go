package httpdebug

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func requestRoutingTLSOrigin(t *testing.T, certificate tls.Certificate, h2 bool, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	server.EnableHTTP2 = h2
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func TestHTTPRequestRoutingHTTP1HTTP2UsesOriginalRequestAndSeparatePools(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprint(h2), func(t *testing.T) {
			certificate, roots := originCertificate(t, "origin.test", false)
			origins := make(map[string]string)
			dials := map[string]*atomic.Int32{"url-outbound": {}, "ua-outbound": {}}
			for _, name := range []string{"url-outbound", "ua-outbound"} {
				origin := requestRoutingTLSOrigin(t, certificate, h2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if (r.ProtoMajor == 2) != h2 {
						t.Errorf("unexpected upstream version %s", r.Proto)
					}
					_, _ = io.WriteString(w, name+":"+r.URL.Path+":"+r.UserAgent())
				}))
				origins[name] = origin.Listener.Addr().String()
			}
			e, store, ca := mitmEngine(t, Config{})
			e.mitm.H2 = h2
			e.httpRouting = &HTTPRoutingConfig{Enabled: true}
			e.rewrite = rewriteProgram(t, `{"enabled":true,"header_rewrite":[{"pattern":"^https://origin\\.test/","phase":"request","operation":"replace_regex","header":"User-Agent","regex":".*","replacement":"changed-agent"},{"pattern":"^https://origin\\.test/","phase":"response","operation":"add","header":"X-Response-Rewrite","value":"yes"}],"url_rewrite":[{"pattern":"^https://origin\\.test/(url|ua|next)$","action":"header","replacement":"https://origin.test/changed"}]}`).RewriteProgram
			var selected atomic.Int32
			route := func(ctx context.Context, request *http.Request) (*RequestRoute, error) {
				selected.Add(1)
				if request.URL.Path == "/reject" {
					return &RequestRoute{RejectResponse: "reject", Metadata: RequestRouteMetadata{Outbound: "reject", Rule: "URL-REGEX reject"}}, nil
				}
				name := "url-outbound"
				if request.URL.Path != "/url" && strings.HasPrefix(request.UserAgent(), "AppB/") {
					name = "ua-outbound"
				}
				return &RequestRoute{Key: name, Metadata: RequestRouteMetadata{Destination: "origin.test:443", Outbound: name, Rule: "original request", Network: "tcp"}, Dial: func(ctx context.Context, address string) (net.Conn, error) {
					if address != "" {
						t.Errorf("same-origin path rewrite changed dial target: %q", address)
					}
					dials[name].Add(1)
					return (&net.Dialer{}).DialContext(ctx, "tcp", origins[name])
				}}, nil
			}
			client, originalDials := mitmClient(t, e, "127.0.0.1:1", ca, roots, h2, route)
			for _, test := range []struct {
				path, agent, want string
				status            int
			}{
				{"url", "AppB/1", "url-outbound:/changed:changed-agent", 200},
				{"ua", "AppB/1", "ua-outbound:/changed:changed-agent", 200},
				{"reject", "AppB/1", "Request rejected by B-box routing\n", 403},
				{"next", "Other", "url-outbound:/changed:changed-agent", 200},
				{"ua", "AppB/2", "ua-outbound:/changed:changed-agent", 200},
			} {
				request, _ := http.NewRequest("GET", "https://origin.test/"+test.path, nil)
				request.Header.Set("User-Agent", test.agent)
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || string(body) != test.want || response.StatusCode != test.status || response.Header.Get("X-Response-Rewrite") != "yes" {
					t.Fatalf("%s: %d %q %v", test.path, response.StatusCode, body, err)
				}
			}
			if originalDials.Load() != 0 || selected.Load() != 5 || dials["url-outbound"].Load() != 1 || dials["ua-outbound"].Load() != 1 {
				t.Fatalf("request routing or pool reuse failed: original=%d selected=%d A=%d B=%d", originalDials.Load(), selected.Load(), dials["url-outbound"].Load(), dials["ua-outbound"].Load())
			}
			for _, item := range waitComplete(t, store, 5) {
				if item.ConnectionID != "mitm-client-1" || item.Outbound != "selected-route" || item.Rule != "selected-rule" || item.RequestRoute == nil {
					t.Fatalf("original connection and request route were conflated: %+v", item)
				}
				if item.Status == 403 && item.RequestRoute.Outbound != "reject" {
					t.Fatalf("rejected request route missing: %+v", item)
				}
			}
		})
	}
}

func TestHTTPRequestRoutingCrossOriginRewriteUsesDefaultPortAndOriginalPolicy(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, scheme := range []string{"http", "https"} {
			t.Run(fmt.Sprintf("%s-http2-%v", scheme, h2), func(t *testing.T) {
				certificate, roots := originCertificate(t, "mapped.test", false)
				handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
					if request.Host != "mapped.test" || request.URL.Path != "/changed" || request.UserAgent() != "rewritten-agent" {
						t.Errorf("rewrite was not sent to the mapped origin: %s %s %s", request.Host, request.URL.Path, request.UserAgent())
					}
					if scheme == "https" && (request.ProtoMajor == 2) != h2 {
						t.Errorf("unexpected upstream version: %s", request.Proto)
					}
					_, _ = io.WriteString(w, "original-policy:mapped-origin")
				})
				var origin *httptest.Server
				if scheme == "https" {
					origin = requestRoutingTLSOrigin(t, certificate, h2, handler)
				} else {
					origin = httptest.NewServer(handler)
					t.Cleanup(origin.Close)
				}
				e, store, ca := mitmEngine(t, Config{})
				e.mitm.H2 = h2
				e.httpRouting = &HTTPRoutingConfig{Enabled: true}
				e.rewrite = rewriteProgram(t, `{"enabled":true,"header_rewrite":[{"pattern":"^https://origin\\.test/route$","phase":"request","operation":"replace_regex","header":"User-Agent","regex":".*","replacement":"rewritten-agent"}],"url_rewrite":[{"pattern":"^https://origin\\.test/route$","action":"header","replacement":"`+scheme+`://mapped.test/changed"}]}`).RewriteProgram
				wantDestination := "mapped.test:80"
				if scheme == "https" {
					wantDestination = "mapped.test:443"
				}
				var selected, mappedDials atomic.Int32
				route := func(ctx context.Context, request *http.Request) (*RequestRoute, error) {
					selected.Add(1)
					if request.URL.String() != "https://origin.test/route" || request.UserAgent() != "original-agent" {
						return nil, fmt.Errorf("policy selected after request rewrite: %s %s", request.URL, request.UserAgent())
					}
					return &RequestRoute{
						Key:      "original-policy",
						Metadata: RequestRouteMetadata{Destination: "origin.test:443", Outbound: "original-policy", Rule: "URL-REGEX original request", Network: "tcp"},
						Dial: func(ctx context.Context, address string) (net.Conn, error) {
							if address != wantDestination {
								return nil, fmt.Errorf("mapped target lacks its correct port: %q, want %q", address, wantDestination)
							}
							mappedDials.Add(1)
							return (&net.Dialer{}).DialContext(ctx, "tcp", origin.Listener.Addr().String())
						},
					}, nil
				}
				client, originalDials := mitmClient(t, e, "127.0.0.1:1", ca, roots, h2, route)
				request, _ := http.NewRequest("GET", "https://origin.test/route", nil)
				request.Header.Set("User-Agent", "original-agent")
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || response.StatusCode != http.StatusOK || string(body) != "original-policy:mapped-origin" {
					t.Fatalf("mapped origin response: %d %q %v", response.StatusCode, body, err)
				}
				if selected.Load() != 1 || mappedDials.Load() != 1 || originalDials.Load() != 0 {
					t.Fatalf("rewritten request rerouted or dialed original outbound: selected=%d mapped=%d original=%d", selected.Load(), mappedDials.Load(), originalDials.Load())
				}
				item := waitComplete(t, store, 1)[0]
				if item.RequestRoute == nil || item.RequestRoute.Outbound != "original-policy" || item.RequestRoute.Destination != wantDestination || item.RequestRoute.Network != "tcp" || item.Outbound != "selected-route" {
					t.Fatalf("captured policy or normalized destination missing: %+v", item)
				}
				detail, err := store.detailWithBodies(item.ID)
				if err != nil || detail.Metadata.RequestRoute == nil || *detail.Metadata.RequestRoute != *item.RequestRoute {
					t.Fatalf("request route details differ from saved summary: %+v %v", detail, err)
				}
			})
		}
	}
}

func TestHTTPRequestRoutingRewrittenDestinationPreservesPortsAndIPv6(t *testing.T) {
	for _, test := range []struct{ address, want string }{
		{"http://mapped.test/changed", "mapped.test:80"},
		{"https://mapped.test/changed", "mapped.test:443"},
		{"https://mapped.test:8443/changed", "mapped.test:8443"},
		{"http://[2001:db8::1]/changed", "[2001:db8::1]:80"},
		{"https://[2001:db8::1]/changed", "[2001:db8::1]:443"},
		{"https://[2001:db8::1]:8443/changed", "[2001:db8::1]:8443"},
	} {
		t.Run(test.address, func(t *testing.T) {
			target, err := url.Parse(test.address)
			if err != nil {
				t.Fatal(err)
			}
			if destination := rewrittenRequestDestination(target); destination != test.want {
				t.Fatalf("mapped destination: %q, want %q", destination, test.want)
			}
		})
	}
}

func TestHTTPRequestRoutingHTTP2ConcurrentPoliciesShareClientConnection(t *testing.T) {
	certificate, roots := originCertificate(t, "origin.test", false)
	started := make(chan struct{}, 12)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	origins := make(map[string]string)
	for _, name := range []string{"A", "B"} {
		origin := requestRoutingTLSOrigin(t, certificate, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/warmup" {
				started <- struct{}{}
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
			}
			_, _ = io.WriteString(w, name)
		}))
		origins[name] = origin.Listener.Addr().String()
	}
	e, store, ca := mitmEngine(t, Config{})
	e.mitm.H2 = true
	e.httpRouting = &HTTPRoutingConfig{Enabled: true}
	route := func(ctx context.Context, r *http.Request) (*RequestRoute, error) {
		name := "A"
		if r.UserAgent() == "B" {
			name = "B"
		}
		return &RequestRoute{Key: name, Metadata: RequestRouteMetadata{Outbound: name, Rule: "USER-AGENT", Destination: "origin.test:443", Network: "tcp"}, Dial: func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", origins[name])
		}}, nil
	}
	client, _ := mitmClient(t, e, "127.0.0.1:1", ca, roots, true, route)
	response, err := client.Get("https://origin.test/warmup")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			name := "A"
			if index%2 != 0 {
				name = "B"
			}
			request, _ := http.NewRequest("GET", "https://origin.test/stream", nil)
			request.Header.Set("User-Agent", name)
			response, err := client.Do(request)
			if err != nil {
				t.Error(err)
				return
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || string(body) != name {
				t.Errorf("crossed concurrent policies: %q/%s %v", body, name, err)
			}
		}(i)
	}
	for i := 0; i < 12; i++ {
		select {
		case <-started:
		case <-time.After(4 * time.Second):
			t.Fatal("different policies did not run concurrently on HTTP/2")
		}
	}
	releaseOnce.Do(func() { close(release) })
	wg.Wait()
	for _, item := range waitComplete(t, store, 13) {
		if item.ConnectionID != "mitm-client-1" || item.RequestRoute == nil {
			t.Fatalf("HTTP/2 request opened a replacement client connection: %+v", item)
		}
	}
}

func TestHTTPRequestRoutingShutdownJoinsLateDial(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	entered, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
	pool := newRequestTransportPool(lifetime, nil, nil, nil, false)
	request, _ := http.NewRequest("GET", "http://example.test/", nil)
	plan := &RequestRoute{Key: "slow", Dial: func(ctx context.Context, _ string) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		<-release
		defer close(exited)
		left, right := net.Pipe()
		right.Close()
		return left, nil
	}}
	returned := make(chan struct{})
	go func() { _, _ = pool.roundTrip(request, plan, ""); close(returned) }()
	<-entered
	cancel()
	closed := make(chan struct{})
	go func() { pool.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("request pool released a still-running route dial")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("request pool did not join cancelled dial")
	}
	<-exited
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("request waited after service shutdown")
	}
}
