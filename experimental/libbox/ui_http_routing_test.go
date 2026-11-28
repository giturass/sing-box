package libbox

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/httpdebug"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestUIHTTPRequestRoutingLibboxTLSRulesAndScript(t *testing.T) {
	const childEnvironment = "BBOX_UI_HTTP_ROUTING_TEST_CHILD"
	if os.Getenv(childEnvironment) != "1" {
		// Processing owns one store directory for a process. Match the existing
		// real binding fixtures instead of resetting its production singleton.
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestUIHTTPRequestRoutingLibboxTLSRulesAndScript$", "-test.count=1", "-test.timeout=45s")
		command.Env = append(os.Environ(), childEnvironment+"=1")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated native TLS routing failed: %v\n%s", err, output)
		}
		return
	}
	directory := t.TempDir()
	for _, h2 := range []bool{false, true} {
		for _, scriptOnly := range []bool{false, true} {
			t.Run(fmt.Sprintf("http2-%v-script-only-%v", h2, scriptOnly), func(t *testing.T) {
				uiHTTPRequestRoutingLibboxTLS(t, directory, h2, scriptOnly)
			})
		}
	}
}

func uiHTTPRequestRoutingLibboxTLS(t *testing.T, directory string, h2, scriptOnly bool) {
	t.Helper()
	const hostname = "native.request.test"
	originCertificate, originCA := uiHTTPRequestRoutingOriginCertificate(t, hostname)
	origins := make(map[string]*httptest.Server)
	requests := make(map[string]*atomic.Int32)
	for _, tag := range []string{"url-outbound", "ua-outbound", "script-outbound"} {
		count := &atomic.Int32{}
		requests[tag] = count
		origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			count.Add(1)
			if (request.ProtoMajor == 2) != h2 {
				t.Errorf("native TLS upstream protocol: %s", request.Proto)
			}
			if request.Host != hostname || request.URL.Path != "/changed" || request.UserAgent() != "changed-agent" {
				t.Errorf("upstream did not receive the subsequent rewrite: %s %s %q", request.Host, request.URL.Path, request.UserAgent())
			}
			_, _ = io.WriteString(w, tag+":"+request.URL.Path+":"+request.UserAgent())
		}))
		origin.TLS = &tls.Config{Certificates: []tls.Certificate{originCertificate}}
		origin.EnableHTTP2 = h2
		origin.StartTLS()
		t.Cleanup(origin.Close)
		origins[tag] = origin
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	platform := testUICaptureSigner{key: key}
	mitmCertificate, err := GenerateUICaptureCA(public, platform)
	if err != nil {
		t.Fatal(err)
	}
	clientRoots := x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM([]byte(mitmCertificate)) {
		t.Fatal("invalid platform MITM CA")
	}
	selectRoute := func(condition map[string]any, tag string) map[string]any {
		address := M.ParseSocksaddr(origins[tag].Listener.Addr().String())
		condition["action"], condition["outbound"] = "route", tag
		condition["override_address"], condition["override_port"] = address.AddrString(), address.Port
		return condition
	}
	finalReject := map[string]any{"action": "reject", "no_drop": true}
	rules := []any{
		selectRoute(map[string]any{"http_url_regex": []string{`/url$`}}, "url-outbound"),
		selectRoute(map[string]any{"http_user_agent": []string{"AppB/*"}}, "ua-outbound"),
		// The script is evaluated before a failed AND branch and then referenced
		// again by the next rule. One request must execute the script only once.
		selectRoute(map[string]any{"type": "logical", "mode": "and", "rules": []any{
			map[string]any{"script": "path"}, map[string]any{"http_url_regex": []string{`/never$`}},
		}}, "url-outbound"),
		selectRoute(map[string]any{"script": "path"}, "script-outbound"),
		finalReject,
	}
	if scriptOnly {
		// No URL/UA condition may incidentally reserve the pending connection.
		rules = []any{selectRoute(map[string]any{"script": "path"}, "script-outbound"), finalReject}
	}
	namespace := fmt.Sprintf("native-http-%v-script-%v", h2, scriptOnly)
	source := `if ($request.url === null) { $done({matched:false}); } else {
if ($request.hostname !== 'native.request.test' || $request.destPort !== 443 || $request.sourcePort !== 4321 ||
$request.sourceIP !== '192.0.2.2' || $request.protocol !== 'HTTPS') throw Error('original request metadata');
var runs = Number($persistentStore.read('native-rule-runs') || 0) + 1;
$persistentStore.write(String(runs), 'native-rule-runs');
$done({matched: $request.url.endsWith('/script') && $request.userAgent === 'Other'}); }`
	profile, err := json.Marshal(map[string]any{
		"outbounds": []any{
			map[string]any{"type": "direct", "tag": "url-outbound"},
			map[string]any{"type": "direct", "tag": "ua-outbound"},
			map[string]any{"type": "direct", "tag": "script-outbound"},
		},
		"certificate": map[string]any{"store": "none", "certificate": []string{originCA}},
		"route":       map[string]any{"rules": rules},
		"experimental": map[string]any{
			"mitm": map[string]any{"enabled": true, "hosts": []string{hostname}, "ports": []uint16{443}, "h2": h2},
			"http_rewrite": map[string]any{"enabled": true,
				"url_rewrite":    []any{map[string]any{"pattern": `^https://native\.request\.test/(url|ua|script)$`, "action": "header", "replacement": "https://native.request.test/changed"}},
				"header_rewrite": []any{map[string]any{"pattern": `^https://native\.request\.test/`, "phase": "request", "operation": "replace_regex", "header": "User-Agent", "regex": ".*", "replacement": "changed-agent"}},
			},
			"scripts": map[string]any{"enabled": true,
				"rule":    []any{map[string]any{"name": "path", "source": source, "storage_namespace": namespace}},
				"generic": []any{map[string]any{"source": `$done($persistentStore.read('native-rule-runs'));`, "storage_namespace": namespace}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := uiProcessingTaskTestServer(t)
	if err = server.StartOrReloadService(string(profile), &OverrideOptions{
		ProcessingDirectory: directory, ScriptTimezone: "UTC", MitmCertificate: mitmCertificate, MitmSigner: platform,
	}); err != nil {
		t.Fatal(err)
	}
	store, err := httpdebug.Saved()
	if err != nil {
		t.Fatal(err)
	}
	store.Clear()
	if err = server.StartUICapture(directory, `{"ports":[443],"bodyLimit":2048}`, "", nil); err != nil {
		t.Fatal(err)
	}
	instance := server.Instance()
	lifetime, cancel := context.WithCancel(instance.Context())
	var clientConnections atomic.Int32
	var routed sync.WaitGroup
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: clientRoots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: h2, MaxConnsPerHost: 1,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			client, inbound, err := uiHTTPRequestRoutingTCPPair(ctx)
			if err != nil {
				return nil, err
			}
			clientConnections.Add(1)
			metadata := adapter.InboundContext{Network: N.NetworkTCP, Inbound: "tun", InboundType: C.TypeTun,
				Protocol: "tls", Domain: hostname, Source: M.ParseSocksaddr("192.0.2.2:4321"),
				Destination: M.ParseSocksaddr("198.51.100.1:443"),
				ProcessInfo: &adapter.ConnectionOwner{UserId: 1234, PackageNames: []string{"com.native"}},
			}
			routed.Add(1)
			go instance.Box().Router().RouteConnectionEx(lifetime, inbound, metadata, N.OnceClose(func(error) { routed.Done() }))
			return client, nil
		},
	}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		cancel()
		if err := server.CloseService(); err != nil {
			t.Error(err)
		}
		joined := make(chan struct{})
		go func() { routed.Wait(); close(joined) }()
		select {
		case <-joined:
		case <-time.After(3 * time.Second):
			t.Error("native TLS routing outlived the service")
		}
	})
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	type sample struct{ path, agent, tag string }
	samples := []sample{{"url", "AppB/1", "url-outbound"}, {"ua", "AppB/1", "ua-outbound"},
		{"script", "Other", "script-outbound"}, {"reject", "Other", "reject"},
		{"script", "Other", "script-outbound"}, {"url", "Other", "url-outbound"}}
	if scriptOnly {
		samples = []sample{{"script", "Other", "script-outbound"}, {"reject", "Other", "reject"}, {"script", "Other", "script-outbound"}}
	}
	wantRequests := make(map[string]int32)
	for _, sample := range samples {
		request, err := http.NewRequest("GET", "https://"+hostname+"/"+sample.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("User-Agent", sample.agent)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		wantStatus, wantBody := 200, sample.tag+":/changed:changed-agent"
		if sample.tag == "reject" {
			wantStatus, wantBody = 403, "Request rejected by B-box routing\n"
		} else {
			wantRequests[sample.tag]++
		}
		if err != nil || response.StatusCode != wantStatus || string(body) != wantBody || (response.ProtoMajor == 2) != h2 {
			t.Fatalf("native %s routing: %d %s %q %v", sample.path, response.StatusCode, response.Proto, body, err)
		}
	}
	if clientConnections.Load() != 1 {
		t.Fatal("HTTP routing or rejection replaced the decrypted client connection", clientConnections.Load())
	}
	for tag, count := range requests {
		if count.Load() != wantRequests[tag] {
			t.Fatalf("request crossed native outbounds: %s=%d, want %d", tag, count.Load(), wantRequests[tag])
		}
	}
	task, err := server.NewUIScriptTask("generic", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { task.Close(); task.Join() }()
	runs, invocationError := uiProcessingTaskTestOutput(t, task)
	if runs != `"3"` || invocationError != "" {
		t.Fatal("native rule script cache crossed requests or executed twice for one evaluation", runs, invocationError)
	}
	var items []httpdebug.Summary
	deadline := time.Now().Add(3 * time.Second)
	for {
		items = store.Page(20, hostname).Items
		complete := len(items) == len(samples)
		for _, item := range items {
			complete = complete && item.Complete
		}
		if complete {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native TLS requests did not finish recording", items)
		}
		time.Sleep(10 * time.Millisecond)
	}
	connectionID := items[0].ConnectionID
	if connectionID == "" {
		t.Fatal("native HTTP routing lost the tracked client connection")
	}
	seenRoutes := make(map[string]int32)
	for _, item := range items {
		if item.ConnectionID != connectionID || item.Outbound != "reject" || item.RequestRoute == nil {
			t.Fatalf("connection rejection and actual HTTP route were conflated: %+v", item)
		}
		decision := item.RequestRoute
		seenRoutes[decision.Outbound]++
		if item.Status == 200 {
			origin := origins[decision.Outbound]
			if origin == nil || !strings.HasSuffix(item.URL, "/changed") || decision.Destination != origin.Listener.Addr().String() || decision.Rule == "" {
				t.Fatalf("original native rule/target was lost after rewriting: %+v", item)
			}
		}
		detail, err := store.Detail(item.ID)
		if err != nil {
			t.Fatal(err)
		}
		if detail.Metadata.Source != "192.0.2.2:4321" || detail.Metadata.UID != 1234 || detail.Metadata.Inbound != "tun" || detail.Metadata.CaptureSource != "MITM" || detail.Metadata.TLS == nil || detail.Metadata.TLS.ServerName != hostname {
			t.Fatalf("libbox TLS routing lost actual source/owner/handshake metadata: %+v", detail.Metadata)
		}
	}
	for tag, count := range wantRequests {
		if seenRoutes[tag] != count {
			t.Fatal("actual request route was not exposed by native capture", seenRoutes, wantRequests)
		}
	}
	if seenRoutes["reject"] != 1 {
		t.Fatal("FINAL REJECT was not captured as the actual request decision", seenRoutes)
	}
}

func uiHTTPRequestRoutingOriginCertificate(t *testing.T, hostname string) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM, err := httpdebug.GenerateCA(key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := httpdebug.ParseCA(rootPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{hostname},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, root.Raw}, PrivateKey: key, Leaf: parsed}, rootPEM
}

func uiHTTPRequestRoutingTCPPair(ctx context.Context) (net.Conn, net.Conn, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	defer listener.Close()
	client, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		return nil, nil, err
	}
	inbound, err := listener.Accept()
	if err != nil {
		client.Close()
		return nil, nil, err
	}
	return client, inbound, nil
}
