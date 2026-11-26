package httpdebug

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type breakpointResult struct {
	status int
	header http.Header
	body   string
	err    error
}

func testBreakpoints(t *testing.T, content string) {
	t.Helper()
	if _, err := SetBreakpoints(content); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		breakpoints.config.Store(nil)
		breakpoints.release()
	})
}

func breakpointRequest(client *http.Client, method, address, body string) <-chan breakpointResult {
	result := make(chan breakpointResult, 1)
	go func() {
		request, err := http.NewRequest(method, address, strings.NewReader(body))
		if err != nil {
			result <- breakpointResult{err: err}
			return
		}
		request.Header.Set("X-Original", "1")
		response, err := client.Do(request)
		if err != nil {
			result <- breakpointResult{err: err}
			return
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		result <- breakpointResult{response.StatusCode, response.Header, string(data), err}
	}()
	return result
}

func waitPaused(t *testing.T) PausedMessage {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if paused := Breakpoints().Paused; len(paused) == 1 {
			return paused[0]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no message paused")
	return PausedMessage{}
}

func waitResult(t *testing.T, result <-chan breakpointResult) breakpointResult {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("request did not finish")
		return breakpointResult{}
	}
}

func breakpointDecision(t *testing.T, value map[string]any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestBreakpointSettingsValidation(t *testing.T) {
	normalized, err := ValidateBreakpoints(`{"enabled":true,"rules":[{"enabled":true,"url":" /Api ","method":"post","request":true,"response":false}]}`)
	if err != nil || !strings.Contains(normalized, `"method":"POST"`) || !strings.Contains(normalized, `"url":"/Api"`) {
		t.Fatalf("settings not normalized: %s %v", normalized, err)
	}
	many := `{"enabled":true,"rules":[` + strings.TrimSuffix(strings.Repeat(`{"enabled":true,"request":true,"response":false},`, maxBreakpointRules+1), ",") + `]}`
	for _, invalid := range []string{
		`null`, `{"enabled":true,"rules":[{"enabled":true,"request":false,"response":false}]}`,
		`{"enabled":true,"rules":[{"enabled":true,"request":true,"response":false,"method":"GET POST"}]}`,
		`{"enabled":true,"rules":[],"scripts":[]}`, many,
	} {
		if _, err = ValidateBreakpoints(invalid); err == nil {
			t.Fatalf("accepted invalid breakpoint settings: %.80s", invalid)
		}
	}
	config := BreakpointConfig{Enabled: true, Rules: []BreakpointRule{{Enabled: true, URL: "/api", Method: "POST", Request: true}, {URL: "", Request: true, Response: true}}}
	if !config.matches(false, "post", "http://example.test/API/items") || config.matches(true, "POST", "http://example.test/api") ||
		config.matches(false, "GET", "http://example.test/api") || config.matches(false, "POST", "http://example.test/other") {
		t.Fatal("rule selection does not follow phase, method and URL")
	}
}

func TestBreakpointPausesAndEditsRequest(t *testing.T) {
	type seen struct{ method, target, host, edit, original, length, body string }
	requests := make(chan seen, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- seen{r.Method, r.URL.RequestURI(), r.Host, r.Header.Get("X-Edit"), r.Header.Get("X-Original"), r.Header.Get("Content-Length"), string(body)}
		_, _ = w.Write([]byte("done"))
	}))
	defer origin.Close()
	e, store := testEngine(t, Config{})
	recordingManager(t, e)
	testBreakpoints(t, `{"enabled":true,"rules":[{"enabled":true,"url":"/pause","method":"post","request":true,"response":false}]}`)
	client := debugClient(t, e, origin.Listener.Addr().String())
	result := breakpointRequest(client, "POST", "http://example.test/pause?x=1", "original")
	paused := waitPaused(t)
	if paused.Phase != "request" || paused.Method != "POST" || paused.URL != "http://example.test/pause?x=1" || !paused.BodyEditable || paused.BodyBytes != 8 || paused.Body != "" {
		t.Fatalf("paused request summary: %+v", paused)
	}
	if state := Status(); state.BreakpointRules != 1 || state.PausedMessages != 1 {
		t.Fatalf("status does not report the breakpoint: %+v", state)
	}
	detail, err := ReadPausedMessage(paused.ID)
	if err != nil || detail.Body != base64.StdEncoding.EncodeToString([]byte("original")) {
		t.Fatalf("paused request detail: %+v %v", detail, err)
	}
	select {
	case <-requests:
		t.Fatal("request reached the server while paused")
	case <-time.After(30 * time.Millisecond):
	}
	for _, invalid := range []map[string]any{
		{"action": "continue", "status": 200}, {"action": "skip"}, {"action": "continue", "method": "CONNECT"},
		{"action": "continue", "url": "ftp://example.test/"}, {"action": "continue", "headers": []Header{{"Bad Name", "1"}}},
		{"action": "continue", "body": "***"},
	} {
		if err = ResolveBreakpoint(paused.ID, breakpointDecision(t, invalid)); err == nil {
			t.Fatalf("accepted invalid decision: %v", invalid)
		}
	}
	if len(Breakpoints().Paused) != 1 {
		t.Fatal("an invalid decision resumed the request")
	}
	err = ResolveBreakpoint(paused.ID, breakpointDecision(t, map[string]any{"action": "continue", "method": "put",
		"url": "http://example.test/edited?y=2", "headers": []Header{{"X-Edit", "yes"}, {"Content-Length", "999"}},
		"body": base64.StdEncoding.EncodeToString([]byte("changed"))}))
	if err != nil {
		t.Fatal(err)
	}
	if got := waitResult(t, result); got.err != nil || got.status != 200 || got.body != "done" {
		t.Fatalf("resumed request failed: %+v", got)
	}
	if got := <-requests; got != (seen{"PUT", "/edited?y=2", "example.test", "yes", "", "7", "changed"}) {
		t.Fatalf("server did not receive the edited request: %+v", got)
	}
	items := waitComplete(t, store, 1)
	d, err := store.detailWithBodies(items[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Request.Method != "PUT" || d.Request.URL != "http://example.test/edited?y=2" || d.OriginalURL != "http://example.test/pause?x=1" ||
		string(d.RequestBody) != "changed" || !strings.Contains(d.Note, "Paused at request breakpoint") || !strings.Contains(d.Note, "Request changed at breakpoint") {
		t.Fatalf("record does not describe the edited request: %+v", d.Exchange)
	}
	if err = ResolveBreakpoint(paused.ID, `{"action":"continue"}`); err == nil {
		t.Fatal("a resumed message could be resolved again")
	}
	if state := Status(); state.PausedMessages != 0 {
		t.Fatal("resumed message is still counted")
	}
}

func TestBreakpointPausesAndEditsResponse(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = writer.Write([]byte("origin"))
	_ = writer.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("X-Origin", "1")
		_, _ = w.Write(compressed.Bytes())
	}))
	defer origin.Close()
	e, store := testEngine(t, Config{})
	testBreakpoints(t, `{"enabled":true,"rules":[{"enabled":true,"request":false,"response":true}]}`)
	client := debugClient(t, e, origin.Listener.Addr().String())

	result := breakpointRequest(client, "GET", "http://example.test/data", "")
	paused := waitPaused(t)
	detail, err := ReadPausedMessage(paused.ID)
	if err != nil || detail.Phase != "response" || detail.Status != 200 || detail.Body != base64.StdEncoding.EncodeToString([]byte("origin")) {
		t.Fatalf("paused response detail: %+v %v", detail, err)
	}
	if err = ResolveBreakpoint(paused.ID, `{"action":"continue","method":"POST"}`); err == nil {
		t.Fatal("a response accepted a request field")
	}
	if err = ResolveBreakpoint(paused.ID, `{"action":"continue"}`); err != nil {
		t.Fatal(err)
	}
	if got := waitResult(t, result); got.err != nil || got.status != 200 || got.body != "origin" || got.header.Get("X-Origin") != "1" {
		t.Fatalf("an unchanged response was altered: %+v", got)
	}

	result = breakpointRequest(client, "GET", "http://example.test/data", "")
	paused = waitPaused(t)
	err = ResolveBreakpoint(paused.ID, breakpointDecision(t, map[string]any{"action": "continue", "status": 418,
		"headers": []Header{{"X-Edit", "yes"}}, "body": base64.StdEncoding.EncodeToString([]byte("edited"))}))
	if err != nil {
		t.Fatal(err)
	}
	got := waitResult(t, result)
	if got.err != nil || got.status != 418 || got.body != "edited" || got.header.Get("X-Edit") != "yes" || got.header.Get("X-Origin") != "" || got.header.Get("Content-Encoding") != "" {
		t.Fatalf("client did not receive the edited response: %+v", got)
	}
	// Pages list the newest record first.
	items := waitComplete(t, store, 2)
	d, err := store.detailWithBodies(items[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Response.Status != 418 || string(d.ResponseBody) != "edited" || !strings.Contains(d.Note, "Response changed at breakpoint") {
		t.Fatalf("record does not describe the edited response: %+v", d.Exchange)
	}
}

func TestBreakpointAbortAndRelease(t *testing.T) {
	var calls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte("done"))
	}))
	defer origin.Close()
	e, store := testEngine(t, Config{})
	recordingManager(t, e)
	const rules = `{"enabled":true,"rules":[{"enabled":true,"request":true,"response":false}]}`
	testBreakpoints(t, rules)
	client := debugClient(t, e, origin.Listener.Addr().String())

	result := breakpointRequest(client, "GET", "http://example.test/abort", "")
	if err := ResolveBreakpoint(waitPaused(t).ID, `{"action":"abort"}`); err != nil {
		t.Fatal(err)
	}
	if got := waitResult(t, result); got.err == nil {
		t.Fatalf("an aborted request returned a response: %+v", got)
	}
	if calls.Load() != 0 {
		t.Fatal("an aborted request reached the server")
	}
	if items := waitComplete(t, store, 1); !strings.Contains(items[0].Error, "aborted at breakpoint") {
		t.Fatalf("abort not recorded: %+v", items[0])
	}

	// Turning breakpoints off forwards what is held, unchanged.
	result = breakpointRequest(client, "GET", "http://example.test/disabled", "")
	waitPaused(t)
	if _, err := SetBreakpoints(`{"enabled":false,"rules":[]}`); err != nil {
		t.Fatal(err)
	}
	if got := waitResult(t, result); got.err != nil || got.body != "done" {
		t.Fatalf("disabling breakpoints did not release the request: %+v", got)
	}

	// Stopping the recording releases too, and an unrecorded request never pauses.
	if _, err := SetBreakpoints(rules); err != nil {
		t.Fatal(err)
	}
	result = breakpointRequest(client, "GET", "http://example.test/stopped", "")
	waitPaused(t)
	Stop()
	if got := waitResult(t, result); got.err != nil || got.body != "done" {
		t.Fatalf("stopping the recording did not release the request: %+v", got)
	}
	if got := waitResult(t, breakpointRequest(client, "GET", "http://example.test/unrecorded", "")); got.err != nil || got.body != "done" {
		t.Fatalf("an unrecorded request was held: %+v", got)
	}
	if state := Status(); state.PausedMessages != 0 || state.BreakpointRules != 1 {
		t.Fatalf("status after release: %+v", state)
	}
}

func TestBreakpointEndsWithEngine(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()
	e, _ := testEngine(t, Config{})
	testBreakpoints(t, `{"enabled":true,"rules":[{"enabled":true,"request":true,"response":true}]}`)
	client := debugClient(t, e, origin.Listener.Addr().String())
	result := breakpointRequest(client, "GET", "http://example.test/closing", "")
	waitPaused(t)
	closed := make(chan struct{})
	go func() { e.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("a paused message kept the engine from closing")
	}
	if got := waitResult(t, result); got.err == nil && got.status == 200 {
		t.Fatalf("a request paused at shutdown was forwarded: %+v", got)
	}
	if len(Breakpoints().Paused) != 0 {
		t.Fatal("a message stayed paused after its engine closed")
	}
}

func TestBreakpointForwardsOversizedRequestBodyUnchanged(t *testing.T) {
	type seen struct {
		edit string
		size int
	}
	requests := make(chan seen, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- seen{r.Header.Get("X-Edit"), len(body)}
	}))
	defer origin.Close()
	e, _ := testEngine(t, Config{})
	recordingManager(t, e)
	testBreakpoints(t, `{"enabled":true,"rules":[{"enabled":true,"request":true,"response":false}]}`)
	client := debugClient(t, e, origin.Listener.Addr().String())
	result := breakpointRequest(client, "POST", "http://example.test/upload", strings.Repeat("a", breakpointBodyLimit+1))
	paused := waitPaused(t)
	if paused.BodyEditable || paused.BodyBytes != 0 {
		t.Fatalf("an oversized body is offered for editing: %+v", paused)
	}
	if err := ResolveBreakpoint(paused.ID, breakpointDecision(t, map[string]any{"action": "continue", "body": ""})); err == nil {
		t.Fatal("a streamed body accepted a replacement")
	}
	err := ResolveBreakpoint(paused.ID, breakpointDecision(t, map[string]any{"action": "continue", "headers": []Header{{"X-Edit", "yes"}}}))
	if err != nil {
		t.Fatal(err)
	}
	if got := waitResult(t, result); got.err != nil || got.status != 200 {
		t.Fatalf("resumed upload failed: %+v", got)
	}
	if got := <-requests; got != (seen{"yes", breakpointBodyLimit + 1}) {
		t.Fatalf("server did not receive the whole upload: %+v", got)
	}
}

func TestBreakpointPausesSlowResponseBodyAsStream(t *testing.T) {
	previous := breakpointBodyWait
	breakpointBodyWait = 50 * time.Millisecond
	defer func() { breakpointBodyWait = previous }()
	finish := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("first "))
		w.(http.Flusher).Flush()
		<-finish
		_, _ = w.Write([]byte("second"))
	}))
	defer origin.Close()
	e, _ := testEngine(t, Config{})
	recordingManager(t, e)
	testBreakpoints(t, `{"enabled":true,"rules":[{"enabled":true,"request":false,"response":true}]}`)
	client := debugClient(t, e, origin.Listener.Addr().String())
	result := breakpointRequest(client, "GET", "http://example.test/events", "")
	paused := waitPaused(t)
	if paused.BodyEditable {
		t.Fatalf("an unfinished body is offered for editing: %+v", paused)
	}
	if err := ResolveBreakpoint(paused.ID, breakpointDecision(t, map[string]any{"action": "continue"})); err != nil {
		t.Fatal(err)
	}
	close(finish)
	if got := waitResult(t, result); got.err != nil || got.body != "first second" {
		t.Fatalf("streamed response changed: %+v", got)
	}
}

type failingBody struct {
	chunks chan string
	closed atomic.Bool
}

func (b *failingBody) Read(p []byte) (int, error) {
	chunk, ok := <-b.chunks
	if !ok {
		return 0, io.ErrUnexpectedEOF
	}
	return copy(p, chunk), nil
}

func (b *failingBody) Close() error {
	b.closed.Store(true)
	return nil
}

func TestHeldBodyReplaysAndReportsLostSource(t *testing.T) {
	source := &failingBody{chunks: make(chan string, 2)}
	source.chunks <- "ab"
	source.chunks <- "cd"
	held := holdBody(source, 1<<10)
	select {
	case <-held.lost:
		t.Fatal("an open source was reported lost")
	case <-time.After(20 * time.Millisecond):
	}
	close(source.chunks)
	select {
	case <-held.lost:
	case <-time.After(2 * time.Second):
		t.Fatal("a failed source was not reported")
	}
	data, err := io.ReadAll(held)
	if string(data) != "abcd" || err != io.ErrUnexpectedEOF {
		t.Fatalf("read %q, %v", data, err)
	}
	if _ = held.Close(); !source.closed.Load() {
		t.Fatal("source left open")
	}

	whole := holdBody(io.NopCloser(strings.NewReader("whole")), 2)
	<-whole.done
	select {
	case <-whole.lost:
		t.Fatal("a complete source was reported lost")
	default:
	}
	if data, err = io.ReadAll(whole); string(data) != "whole" || err != nil {
		t.Fatalf("read %q, %v", data, err)
	}
}
