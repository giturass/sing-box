package httpdebug

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type replaySeen struct {
	method, target, host, agent, header, encoding, body, length string
}

func replayOrigin(t *testing.T) (*httptest.Server, <-chan replaySeen, RewriteDialFunc, *[]string) {
	t.Helper()
	requests := make(chan replaySeen, 4)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, agent := r.Header["User-Agent"]
		requests <- replaySeen{r.Method, r.URL.RequestURI(), r.Host, map[bool]string{true: "sent"}[agent], r.Header.Get("X-A") + r.Header.Get("X-B"),
			r.Header.Get("Content-Encoding"), string(body), r.Header.Get("Content-Length")}
		w.Header().Set("X-Replayed", "1")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("reply:" + string(body)))
	}))
	t.Cleanup(origin.Close)
	dialed := new([]string)
	dial := func(ctx context.Context, address string) (net.Conn, error) {
		*dialed = append(*dialed, address)
		return (&net.Dialer{}).DialContext(ctx, "tcp", origin.Listener.Addr().String())
	}
	return origin, requests, dial, dialed
}

func TestReplayResendsCapturedRequestAsNewRecord(t *testing.T) {
	origin, requests, dial, dialed := replayOrigin(t)
	e, store := testEngine(t, Config{})
	client := debugClient(t, e, origin.Listener.Addr().String())
	request, _ := http.NewRequest("POST", "http://example.test/submit?x=1", strings.NewReader("payload"))
	request.Header.Set("X-A", "1")
	request.Header.Set("Content-Encoding", "identity")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	<-requests
	source := waitComplete(t, store, 1)[0].ID

	result, err := store.Replay(context.Background(), source, `{}`, dial, nil)
	if err != nil || result.ID == "" || result.ID == source || result.Status != http.StatusAccepted || result.Error != "" {
		t.Fatalf("replay result: %+v %v", result, err)
	}
	if got := <-requests; got != (replaySeen{"POST", "/submit?x=1", "example.test", "sent", "1", "identity", "payload", "7"}) {
		t.Fatalf("server did not receive the captured request: %+v", got)
	}
	if len(*dialed) != 1 || (*dialed)[0] != "example.test:80" {
		t.Fatalf("replay did not use the routed destination: %v", *dialed)
	}
	waitComplete(t, store, 2)
	d, err := store.detailWithBodies(result.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Metadata.Inbound != "b-box-replay" || d.Metadata.CaptureSource != "Replay" || d.Metadata.Destination != "example.test:80" || d.Metadata.UID != -1 ||
		!strings.Contains(d.Note, source) || d.Error != "" || d.Request.Method != "POST" || d.Request.URL != "http://example.test/submit?x=1" ||
		string(d.RequestBody) != "payload" || d.Response.Status != http.StatusAccepted || string(d.ResponseBody) != "reply:payload" ||
		headerValue(d.Response, "X-Replayed") != "1" || !d.Request.BodyComplete || !d.Response.BodyComplete {
		t.Fatalf("replay record: %+v", d.Exchange)
	}

	options, _ := json.Marshal(map[string]any{"method": "put", "url": "http://other.test:8080/new", "headers": []Header{{"X-B", "2"}, {"Content-Encoding", "gzip"}, {"Content-Length", "99"}, {"Connection", "close"}},
		"body": base64.StdEncoding.EncodeToString([]byte("edited"))})
	result, err = store.Replay(context.Background(), source, string(options), dial, nil)
	if err != nil || result.Status != http.StatusAccepted || result.Error != "" {
		t.Fatalf("edited replay result: %+v %v", result, err)
	}
	if got := <-requests; got != (replaySeen{"PUT", "/new", "other.test:8080", "", "2", "", "edited", "6"}) {
		t.Fatalf("server did not receive the edited request: %+v", got)
	}
	if (*dialed)[1] != "other.test:8080" {
		t.Fatalf("edited replay destination: %v", *dialed)
	}
	waitComplete(t, store, 3)
	d, err = store.detailWithBodies(result.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Request.Method != "PUT" || string(d.RequestBody) != "edited" || headerValue(d.Request, "User-Agent") != "" || !strings.Contains(d.Note, "Content-Encoding removed") {
		t.Fatalf("edited replay record: %+v", d.Exchange)
	}
}

func TestReplayRejectsWhatItCannotReproduce(t *testing.T) {
	origin, requests, dial, dialed := replayOrigin(t)
	e, store := testEngine(t, Config{BodyLimit: 4})
	client := debugClient(t, e, origin.Listener.Addr().String())
	response, err := client.Post("http://example.test/long", "text/plain", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	<-requests
	source := waitComplete(t, store, 1)[0].ID
	for name, call := range map[string][2]string{
		"truncated body": {source, `{}`}, "unknown record": {strings.Repeat("0", 32), `{}`}, "invalid ID": {"../x", `{}`},
		"unknown option": {source, `{"follow":true}`}, "relative URL": {source, `{"url":"/path","body":""}`},
		"upgrade": {source, `{"headers":[{"name":"Upgrade","value":"websocket"}],"body":""}`},
		"method":  {source, `{"method":"CONNECT","body":""}`}, "body": {source, `{"body":"***"}`},
	} {
		if result, err := store.Replay(context.Background(), call[0], call[1], dial, nil); err == nil {
			t.Fatalf("%s was replayed: %+v", name, result)
		}
	}
	if len(*dialed) != 0 || len(store.Page(0, "").Items) != 1 {
		t.Fatal("a rejected replay dialed or left a record")
	}

	// A replacement body makes a truncated capture replayable; the body limit follows the source.
	result, err := store.Replay(context.Background(), source, `{"body":"bmV3IGJvZHk="}`, dial, nil)
	if err != nil || result.Error != "" {
		t.Fatalf("replay with a replacement body: %+v %v", result, err)
	}
	if got := <-requests; got.body != "new body" || got.length != "8" {
		t.Fatalf("replacement body not sent: %+v", got)
	}
	waitComplete(t, store, 2)
	d, err := store.detailWithBodies(result.ID)
	if err != nil || d.BodyLimit != 4 || string(d.RequestBody) != "new " || !d.Request.BodyTruncated {
		t.Fatalf("replay record ignores the source body limit: %+v %v", d, err)
	}

	// A failed send still leaves a record that explains it.
	failing := func(context.Context, string) (net.Conn, error) { return nil, errors.New("route rejected") }
	result, err = store.Replay(context.Background(), source, `{"body":""}`, failing, nil)
	if err != nil || result.ID == "" || !strings.Contains(result.Error, "route rejected") || result.Status != 0 {
		t.Fatalf("failed replay result: %+v %v", result, err)
	}
	// Pages list the newest record first.
	items := waitComplete(t, store, 3)
	if items[0].ID != result.ID || !strings.Contains(items[0].Error, "route rejected") {
		t.Fatalf("failed replay record: %+v", items[0])
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err = store.Replay(cancelled, source, `{"body":""}`, dial, nil); err != nil || result.Error == "" {
		t.Fatalf("cancelled replay result: %+v %v", result, err)
	}
	waitComplete(t, store, 4)
}
