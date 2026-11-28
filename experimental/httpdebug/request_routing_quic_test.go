//go:build with_quic

package httpdebug

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
)

func TestHTTPRequestRoutingHTTP3ConcurrentPoliciesAndRejectReuse(t *testing.T) {
	certificate, roots := originCertificate(t, "origin.test", false)
	origins := make(map[string]*net.UDPAddr)
	dials := map[string]*atomic.Int32{"A": {}, "B": {}}
	started := make(chan struct{}, 8)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	for _, name := range []string{"A", "B"} {
		address := http3TestOrigin(t, certificate, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor != 3 {
				t.Errorf("request left HTTP/3 unexpectedly: %s", r.Proto)
			}
			if r.URL.Path == "/changed" {
				started <- struct{}{}
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
			}
			_, _ = io.WriteString(w, name+":"+r.UserAgent())
		}))
		peer, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			t.Fatal(err)
		}
		origins[name] = peer
	}
	e, store, ca := mitmEngine(t, Config{})
	e.mitm = mitmConfig(t, `{"enabled":true,"hosts":["origin.test"],"h3":true}`)
	e.httpRouting = &HTTPRoutingConfig{Enabled: true}
	e.rewrite = rewriteProgram(t, `{"enabled":true,"header_rewrite":[{"pattern":"/request","phase":"request","operation":"replace_regex","header":"User-Agent","regex":".*","replacement":"changed"}],"url_rewrite":[{"pattern":"^https://origin\\.test/request/[0-9]+$","action":"header","replacement":"https://origin.test/changed"}]}`).RewriteProgram
	var selections atomic.Int32
	route := func(ctx context.Context, r *http.Request) (*RequestRoute, error) {
		selections.Add(1)
		if r.URL.Path == "/reject" {
			return &RequestRoute{RejectResponse: "reject", Metadata: RequestRouteMetadata{Outbound: "reject", Rule: "URL-REGEX"}}, nil
		}
		name := "A"
		if strings.HasPrefix(r.UserAgent(), "B/") {
			name = "B"
		}
		return &RequestRoute{Key: name, Metadata: RequestRouteMetadata{Outbound: name, Rule: "USER-AGENT", Destination: "origin.test:443", Network: "udp"}, PacketDial: func(ctx context.Context, address string) (net.PacketConn, net.Addr, error) {
			if address != "" {
				t.Errorf("HTTP/3 path rewrite changed origin: %q", address)
			}
			dials[name].Add(1)
			raw, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				return nil, nil, err
			}
			context.AfterFunc(ctx, func() { _ = raw.Close() })
			return raw, origins[name], nil
		}}, nil
	}
	client, originalDials := http3TestClient(t, e, "127.0.0.1:1", ca, roots, quic.Version1, nil, route)
	response, err := client.Get("https://origin.test/reject")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatalf("wrong request rejection status %d", response.StatusCode)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			name := "A"
			if index%2 != 0 {
				name = "B"
			}
			request, _ := http.NewRequest("GET", fmt.Sprintf("https://origin.test/request/%d", index), nil)
			request.Header.Set("User-Agent", name+"/original")
			response, err := client.Do(request)
			if err != nil {
				t.Error(err)
				return
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || string(body) != name+":changed" {
				t.Errorf("HTTP/3 crossed policies or matched rewritten User-Agent: %q %v", body, err)
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("HTTP/3 policies did not run independently")
		}
	}
	releaseOnce.Do(func() { close(release) })
	wg.Wait()
	if originalDials.Load() != 0 || selections.Load() != 9 || dials["A"].Load() != 1 || dials["B"].Load() != 1 {
		t.Fatalf("HTTP/3 request selection/pool isolation: original=%d selections=%d A=%d B=%d", originalDials.Load(), selections.Load(), dials["A"].Load(), dials["B"].Load())
	}
	for _, item := range waitComplete(t, store, 9) {
		if item.ConnectionID != "quic-original-connection" || item.Outbound != "selected-udp-route" || item.RequestRoute == nil {
			t.Fatalf("HTTP/3 lost original connection/request route: %+v", item)
		}
		if item.Status == 200 && item.RequestRoute.Network != "udp" {
			t.Fatalf("HTTP/3 actual route was not retained: %+v", item)
		}
	}
}
