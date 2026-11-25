package httpdebug

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http/httpguts"
)

const (
	breakpointBodyLimit = 1 << 20
	maxBreakpointRules  = 64
	maxPausedMessages   = 64
)

var errBreakpointAbort = errors.New("HTTP exchange aborted at breakpoint")

// Framing follows the body that is actually forwarded, never an edited header.
var breakpointFramingHeaders = []string{"Content-Length", "Transfer-Encoding", "Trailer", "Content-Encoding"}

// BreakpointRule selects parsed HTTP messages. URL is a case-insensitive
// substring of the absolute request URL; an empty value matches every URL.
type BreakpointRule struct {
	Enabled  bool   `json:"enabled"`
	URL      string `json:"url,omitempty"`
	Method   string `json:"method,omitempty"`
	Request  bool   `json:"request"`
	Response bool   `json:"response"`
}

// BreakpointConfig lives in process memory only. A restarted process never
// holds traffic for a user who is no longer watching.
type BreakpointConfig struct {
	Enabled bool             `json:"enabled"`
	Rules   []BreakpointRule `json:"rules"`
}

func (c *BreakpointConfig) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errors.New("breakpoint settings must be an object")
	}
	type plain BreakpointConfig
	var value plain
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	*c = BreakpointConfig(value)
	return c.validate()
}

func (c *BreakpointConfig) validate() error {
	if c.Rules == nil {
		c.Rules = []BreakpointRule{}
	}
	if len(c.Rules) > maxBreakpointRules {
		return fmt.Errorf("at most %d breakpoint rules are supported", maxBreakpointRules)
	}
	for i := range c.Rules {
		rule := &c.Rules[i]
		rule.URL = strings.TrimSpace(rule.URL)
		rule.Method = strings.ToUpper(strings.TrimSpace(rule.Method))
		if len(rule.URL) > 2048 || strings.ContainsFunc(rule.URL, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return errors.New("breakpoint URL filter is invalid")
		}
		if rule.Method != "" && !httpguts.ValidHeaderFieldName(rule.Method) {
			return errors.New("breakpoint method filter is invalid")
		}
		if !rule.Request && !rule.Response {
			return errors.New("a breakpoint rule must pause requests or responses")
		}
	}
	return nil
}

func (c *BreakpointConfig) matches(response bool, method, address string) bool {
	if c == nil || !c.Enabled {
		return false
	}
	address = strings.ToLower(address)
	for _, rule := range c.Rules {
		if !rule.Enabled || response && !rule.Response || !response && !rule.Request {
			continue
		}
		if rule.Method != "" && rule.Method != strings.ToUpper(method) {
			continue
		}
		if rule.URL == "" || strings.Contains(address, strings.ToLower(rule.URL)) {
			return true
		}
	}
	return false
}

// PausedMessage is one HTTP message held before it is forwarded. Body carries
// the decoded content and is present only in a detail read.
type PausedMessage struct {
	ID           string   `json:"id"`
	ExchangeID   string   `json:"exchangeId,omitempty"`
	Phase        string   `json:"phase"`
	PausedAt     int64    `json:"pausedAt"`
	Method       string   `json:"method"`
	URL          string   `json:"url"`
	Status       int      `json:"status,omitempty"`
	Headers      []Header `json:"headers"`
	BodyEditable bool     `json:"bodyEditable"`
	BodyBytes    int64    `json:"bodyBytes"`
	Body         string   `json:"body,omitempty"`
	body         []byte
	decision     chan BreakpointDecision
}

// BreakpointDecision resumes or aborts a paused message. Absent fields keep the
// paused value; Body is Base64 of the decoded replacement content.
type BreakpointDecision struct {
	Action  string    `json:"action"`
	Method  *string   `json:"method,omitempty"`
	URL     *string   `json:"url,omitempty"`
	Status  *int      `json:"status,omitempty"`
	Headers *[]Header `json:"headers,omitempty"`
	Body    *string   `json:"body,omitempty"`
	body    []byte
}

type BreakpointSnapshot struct {
	Config BreakpointConfig `json:"config"`
	Paused []PausedMessage  `json:"paused"`
}

var breakpoints breakpointRegistry

type breakpointRegistry struct {
	config atomic.Pointer[BreakpointConfig]
	mu     sync.Mutex
	paused map[string]*PausedMessage
	order  []string
}

func ValidateBreakpoints(content string) (string, error) {
	var config BreakpointConfig
	if err := json.Unmarshal([]byte(content), &config); err != nil {
		return "", err
	}
	data, err := json.Marshal(config)
	return string(data), err
}

// SetBreakpoints replaces the rules for new messages. Disabling them releases
// every message that is already paused, unchanged.
func SetBreakpoints(content string) (BreakpointSnapshot, error) {
	var config BreakpointConfig
	if err := json.Unmarshal([]byte(content), &config); err != nil {
		return BreakpointSnapshot{}, err
	}
	breakpoints.config.Store(&config)
	if !config.Enabled {
		breakpoints.release()
	}
	return Breakpoints(), nil
}

// release forwards every held message unchanged.
func (r *breakpointRegistry) release() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, message := range r.paused {
		select {
		case message.decision <- BreakpointDecision{Action: "continue"}:
		default:
		}
	}
}

func Breakpoints() BreakpointSnapshot {
	snapshot := BreakpointSnapshot{Config: BreakpointConfig{Rules: []BreakpointRule{}}, Paused: []PausedMessage{}}
	if config := breakpoints.config.Load(); config != nil {
		snapshot.Config = BreakpointConfig{Enabled: config.Enabled, Rules: append([]BreakpointRule{}, config.Rules...)}
	}
	breakpoints.mu.Lock()
	defer breakpoints.mu.Unlock()
	for _, id := range breakpoints.order {
		if message := breakpoints.paused[id]; message != nil {
			snapshot.Paused = append(snapshot.Paused, message.public(false))
		}
	}
	return snapshot
}

func ReadPausedMessage(id string) (*PausedMessage, error) {
	breakpoints.mu.Lock()
	defer breakpoints.mu.Unlock()
	message := breakpoints.paused[id]
	if message == nil {
		return nil, errors.New("this message is no longer paused")
	}
	value := message.public(true)
	return &value, nil
}

// ResolveBreakpoint validates against the paused message, so an invalid edit is
// reported to the editor instead of failing the held exchange.
func ResolveBreakpoint(id, content string) error {
	var decision BreakpointDecision
	decoder := json.NewDecoder(strings.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decision); err != nil {
		return err
	}
	breakpoints.mu.Lock()
	defer breakpoints.mu.Unlock()
	message := breakpoints.paused[id]
	if message == nil {
		return errors.New("this message is no longer paused")
	}
	if err := decision.validate(message); err != nil {
		return err
	}
	select {
	case message.decision <- decision:
		return nil
	default:
		return errors.New("this message is already being resumed")
	}
}

func (d *BreakpointDecision) validate(message *PausedMessage) error {
	if d.Action == "abort" {
		*d = BreakpointDecision{Action: "abort"}
		return nil
	}
	if d.Action != "continue" {
		return errors.New("unknown breakpoint action")
	}
	response := message.Phase == "response"
	if response && (d.Method != nil || d.URL != nil) || !response && d.Status != nil {
		return errors.New("this field cannot be changed in the paused phase")
	}
	if d.Method != nil {
		*d.Method = strings.ToUpper(strings.TrimSpace(*d.Method))
		if !httpguts.ValidHeaderFieldName(*d.Method) || *d.Method == http.MethodConnect {
			return errors.New("unsupported HTTP method")
		}
	}
	if d.URL != nil {
		if _, err := parseRewriteURL(*d.URL); err != nil {
			return errors.New("enter an absolute HTTP(S) URL without credentials or a fragment")
		}
	}
	if d.Status != nil && (*d.Status < 200 || *d.Status > 599) {
		return errors.New("status must be between 200 and 599")
	}
	if d.Headers != nil {
		if err := validMessageHeaders(*d.Headers); err != nil {
			return err
		}
	}
	if d.Body != nil {
		if !message.BodyEditable {
			return errors.New("this body is streamed unchanged and cannot be edited")
		}
		body, err := base64.StdEncoding.DecodeString(*d.Body)
		if err != nil {
			return errors.New("invalid Base64 body")
		}
		if len(body) > breakpointBodyLimit {
			return fmt.Errorf("an edited body is limited to %d bytes", breakpointBodyLimit)
		}
		d.body = body
	}
	return nil
}

func validMessageHeaders(headers []Header) error {
	for _, header := range headers {
		if !httpguts.ValidHeaderFieldName(header.Name) || strings.HasPrefix(header.Name, ":") || !httpguts.ValidHeaderFieldValue(header.Value) {
			return fmt.Errorf("invalid header %q", header.Name)
		}
	}
	return nil
}

func (m *PausedMessage) public(body bool) PausedMessage {
	value := *m
	value.Headers = append([]Header{}, m.Headers...)
	value.body, value.decision = nil, nil
	if body && m.BodyEditable {
		value.Body = base64.StdEncoding.EncodeToString(m.body)
	}
	return value
}

func (r *breakpointRegistry) add(message *PausedMessage) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.paused) >= maxPausedMessages {
		return false
	}
	if r.paused == nil {
		r.paused = make(map[string]*PausedMessage)
	}
	message.ID = rand.Text()
	message.PausedAt = time.Now().UnixMilli()
	message.decision = make(chan BreakpointDecision, 1)
	r.paused[message.ID] = message
	r.order = append(r.order, message.ID)
	return true
}

func (r *breakpointRegistry) remove(message *PausedMessage) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.paused, message.ID)
	for i, id := range r.order {
		if id == message.ID {
			r.order = append(r.order[:i], r.order[i+1:]...)
			break
		}
	}
}

func (r *breakpointRegistry) count() (rules, paused int) {
	if config := r.config.Load(); config != nil && config.Enabled {
		for _, rule := range config.Rules {
			if rule.Enabled {
				rules++
			}
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return rules, len(r.paused)
}

// Only a message of a recorded exchange pauses, so the list always shows what
// is being held. Stopping the recording releases it.
func (e *Engine) breakpoint(response bool, request *http.Request, id string) bool {
	return id != "" && e.recording.Load() != nil &&
		breakpoints.config.Load().matches(response, request.Method, request.URL.String())
}

// hold blocks until the user decides, the client gives up, or this engine ends.
func (e *Engine) hold(request *http.Request, message *PausedMessage, note func(string)) (BreakpointDecision, bool, error) {
	if !breakpoints.add(message) {
		note("Breakpoint skipped: too many paused messages")
		return BreakpointDecision{}, false, nil
	}
	defer breakpoints.remove(message)
	if e.recording.Load() == nil {
		return BreakpointDecision{}, false, nil
	}
	note("Paused at " + message.Phase + " breakpoint")
	select {
	case decision := <-message.decision:
		return decision, true, nil
	case <-request.Context().Done():
		return BreakpointDecision{}, false, request.Context().Err()
	case <-e.ctx.Done():
		return BreakpointDecision{}, false, errors.New("local service stopped at breakpoint")
	}
}

func pausedBody(request *http.Request, header http.Header, body *io.ReadCloser, response bool) ([]byte, bool, error) {
	if response && request.Method == http.MethodHead {
		return nil, false, nil
	}
	if !bodyEligible(header, func(string) {}, false) {
		return nil, false, nil
	}
	return readRewriteBody(request.Context(), body, contentEncoding(header), breakpointBodyLimit, true, func(string) {})
}

func editedHeaders(original http.Header, headers []Header) http.Header {
	result := make(http.Header, len(headers))
	for _, header := range headers {
		name := http.CanonicalHeaderKey(header.Name)
		if name == "Host" {
			continue
		}
		result[name] = append(result[name], header.Value)
	}
	for _, name := range breakpointFramingHeaders {
		result.Del(name)
		if values := original.Values(name); len(values) > 0 {
			result[name] = append([]string(nil), values...)
		}
	}
	return result
}

// pauseRequest holds the request that would be sent upstream, after profile
// rewrites and scripts. It reports whether the user changed it.
func (e *Engine) pauseRequest(request *http.Request, id string, note func(string)) (bool, error) {
	if !e.breakpoint(false, request, id) {
		return false, nil
	}
	body, editable, err := pausedBody(request, request.Header, &request.Body, false)
	if err != nil {
		return false, err
	}
	headers, _ := captureHeaders(request.Header, "")
	message := &PausedMessage{ExchangeID: id, Phase: "request", Method: request.Method, URL: request.URL.String(),
		Headers: headers, BodyEditable: editable, BodyBytes: int64(len(body)), body: body}
	decision, decided, err := e.hold(request, message, note)
	if err != nil || !decided {
		return false, err
	}
	if decision.Action == "abort" {
		return false, errBreakpointAbort
	}
	changed := false
	if decision.Method != nil && *decision.Method != request.Method {
		request.Method, changed = *decision.Method, true
	}
	if decision.URL != nil && *decision.URL != request.URL.String() {
		target, err := parseRewriteURL(*decision.URL)
		if err != nil {
			return false, err
		}
		if target.Host != request.URL.Host {
			request.Host = target.Host
		}
		request.URL, changed = target, true
	}
	if decision.Headers != nil {
		request.Header, changed = editedHeaders(request.Header, *decision.Headers), true
	}
	if decision.Body != nil && !bytes.Equal(decision.body, body) {
		replaceRequestBody(request, decision.body)
		changed = true
	}
	if changed {
		if err = validRewriteRequest(request); err != nil {
			return false, err
		}
		note("Request changed at breakpoint")
	}
	return changed, nil
}

// pauseResponse holds the response that would be returned to the client.
func (e *Engine) pauseResponse(request *http.Request, response *http.Response, id string, note func(string)) error {
	if response.StatusCode == http.StatusSwitchingProtocols || !e.breakpoint(true, request, id) {
		return nil
	}
	body, editable, err := pausedBody(request, response.Header, &response.Body, true)
	if err != nil {
		return err
	}
	headers, _ := captureHeaders(response.Header, "")
	message := &PausedMessage{ExchangeID: id, Phase: "response", Method: request.Method, URL: request.URL.String(),
		Status: response.StatusCode, Headers: headers, BodyEditable: editable, BodyBytes: int64(len(body)), body: body}
	decision, decided, err := e.hold(request, message, note)
	if err != nil || !decided {
		return err
	}
	if decision.Action == "abort" {
		return errBreakpointAbort
	}
	changed := false
	if decision.Status != nil && *decision.Status != response.StatusCode {
		response.StatusCode, changed = *decision.Status, true
		response.Status = fmt.Sprintf("%d %s", response.StatusCode, http.StatusText(response.StatusCode))
	}
	if decision.Headers != nil {
		response.Header, changed = editedHeaders(response.Header, *decision.Headers), true
	}
	if decision.Body != nil && !bytes.Equal(decision.body, body) {
		replaceResponseBody(response, decision.body)
		changed = true
	}
	if changed {
		normalizeResponseBody(request, response)
		note("Response changed at breakpoint")
	}
	return nil
}
