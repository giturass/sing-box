package httpdebug

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const (
	replayBodyLimit = 1 << 20
	replayInbound   = "b-box-replay"
)

// ReplayOptions overrides parts of a captured request. Absent fields resend the
// captured value; Body is Base64 of the bytes to send, without a content coding.
type ReplayOptions struct {
	Method  *string   `json:"method,omitempty"`
	URL     *string   `json:"url,omitempty"`
	Headers *[]Header `json:"headers,omitempty"`
	Body    *string   `json:"body,omitempty"`
}

// ReplayResult names the new record. Error repeats the record's failure, so the
// caller can still open what was sent.
type ReplayResult struct {
	ID     string `json:"id"`
	Status int    `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Replay sends one captured request again through dial and records it as a new
// exchange. Profile rewrites, scripts and breakpoints never apply to a replay,
// and a redirect is recorded, not followed.
func (s *Store) Replay(ctx context.Context, id, optionsJSON string, dial RewriteDialFunc, roots *x509.CertPool) (ReplayResult, error) {
	var options ReplayOptions
	decoder := json.NewDecoder(strings.NewReader(optionsJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&options); err != nil {
		return ReplayResult{}, err
	}
	if !validID(id) {
		return ReplayResult{}, errors.New("invalid request ID")
	}
	source, err := s.snapshot(id)
	if errors.Is(err, os.ErrNotExist) {
		return ReplayResult{}, errors.New("this request is no longer saved")
	}
	if err != nil {
		return ReplayResult{}, err
	}
	// The captured body is streamed from this snapshot until the send ends.
	defer source.close()
	request, notes, err := source.replayRequest(ctx, options)
	if err != nil {
		return ReplayResult{}, err
	}
	limit := source.BodyLimit
	if limit == 0 {
		limit = DefaultBodyLimit
	}
	result := ReplayResult{ID: s.begin(replayMetadata(request.URL), request, limit)}
	if result.ID == "" {
		return ReplayResult{}, errors.New("could not create the replay record")
	}
	defer s.finish(result.ID)
	s.addNote(result.ID, "Replay of request "+id+" through sing-box routing; rewrites, scripts and breakpoints are not applied")
	for _, note := range notes {
		s.addNote(result.ID, note)
	}
	if _, found := request.Header["User-Agent"]; !found {
		// net/http otherwise adds its own; the record keeps the list as sent.
		request.Header["User-Agent"] = []string{""}
	}
	if request.Body != http.NoBody {
		request.Body = &tapBody{ReadCloser: request.Body, store: s, id: result.ID, expected: request.ContentLength}
	}
	transport := newRewriteTransport(ctx, dial, roots)
	defer transport.CloseIdleConnections()
	response, err := transport.RoundTrip(request)
	if err != nil {
		s.setError(result.ID, err)
		result.Error = err.Error()
		return result, nil
	}
	result.Status = response.StatusCode
	s.mu.Lock()
	if record := s.records[result.ID]; record != nil && !record.finishing && !record.Complete {
		record.Request.Protocol = response.Proto
	}
	s.mu.Unlock()
	s.response(result.ID, response)
	if response.StatusCode == http.StatusSwitchingProtocols {
		response.Body.Close()
		return result, nil
	}
	body := &tapBody{ReadCloser: response.Body, store: s, id: result.ID, response: true, expected: response.ContentLength, trailers: response.Trailer}
	_, err = io.Copy(io.Discard, body)
	body.Close()
	if err != nil {
		result.Error = err.Error()
	}
	return result, nil
}

func (d *bodySnapshot) replayRequest(ctx context.Context, options ReplayOptions) (*http.Request, []string, error) {
	if d.DomainOnly || d.Metadata.RawTCP || !strings.HasPrefix(d.Request.Protocol, "HTTP/") {
		return nil, nil, errors.New("only a parsed HTTP request can be replayed")
	}
	method, address := d.Request.Method, d.Request.URL
	if options.Method != nil {
		method = strings.ToUpper(strings.TrimSpace(*options.Method))
	}
	if options.URL != nil {
		address = strings.TrimSpace(*options.URL)
	}
	target, err := parseRewriteURL(address)
	if err != nil {
		return nil, nil, errors.New("replay needs an absolute HTTP(S) URL without credentials or a fragment")
	}
	headers := d.Request.Headers
	if options.Headers != nil {
		headers = *options.Headers
	} else if d.Request.HeadersTruncated {
		return nil, nil, errors.New("captured request headers are truncated; enter the headers to replay")
	}
	if err = validMessageHeaders(headers); err != nil {
		return nil, nil, err
	}
	var body io.Reader
	var length int64
	if options.Body != nil {
		data, err := base64.StdEncoding.DecodeString(*options.Body)
		if err != nil {
			return nil, nil, errors.New("invalid Base64 body")
		}
		if len(data) > replayBodyLimit {
			return nil, nil, fmt.Errorf("a replacement body is limited to %d bytes", replayBodyLimit)
		}
		body, length = bytes.NewReader(data), int64(len(data))
	} else {
		if !d.Request.BodyComplete || d.Request.BodyTruncated {
			return nil, nil, errors.New("captured request body is incomplete; enter a replacement body to replay")
		}
		if len(d.Request.Trailers) > 0 || d.Request.TrailersTruncated {
			return nil, nil, errors.New("request trailers cannot be replayed; enter a replacement body")
		}
		body, length = d.reader(false), d.Request.CapturedBytes
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return nil, nil, err
	}
	request.ContentLength, request.GetBody = length, nil
	if length == 0 {
		request.Body = http.NoBody
	}
	var notes []string
	for _, header := range headers {
		name := http.CanonicalHeaderKey(header.Name)
		switch name {
		case "Host":
			// A captured Host belongs to the captured URL, not to a new one.
			if options.URL == nil || options.Headers != nil {
				request.Host = header.Value
			}
		case "Upgrade":
			return nil, nil, errors.New("a protocol upgrade request cannot be replayed")
		case "Content-Length", "Transfer-Encoding", "Trailer", "Connection", "Proxy-Connection", "Keep-Alive":
			// Framing and hop-by-hop fields describe the captured connection.
		case "Te":
			if strings.EqualFold(strings.TrimSpace(header.Value), "trailers") {
				request.Header.Add(name, header.Value)
			}
		case "Content-Encoding":
			if options.Body != nil {
				notes = append(notes, "Content-Encoding removed: the replacement body is sent as entered")
			} else {
				request.Header.Add(name, header.Value)
			}
		default:
			request.Header.Add(name, header.Value)
		}
	}
	if err = validRewriteRequest(request); err != nil {
		return nil, nil, errors.New("replay needs a valid method, URL and Host")
	}
	return request, notes, nil
}

func replayMetadata(target *url.URL) Metadata {
	host, port := normalizeHost(target.Hostname()), target.Port()
	metadata := Metadata{Host: host, Protocol: "http", Inbound: replayInbound, UID: -1, Packages: []string{}, CaptureSource: "Replay"}
	if target.Scheme == "https" {
		metadata.Protocol, metadata.TLS = "tls", &TLSMetadata{ServerName: host}
	}
	if port == "" {
		port = "80"
		if target.Scheme == "https" {
			port = "443"
		}
	}
	number, _ := strconv.ParseUint(port, 10, 16)
	metadata.Port, metadata.Destination = uint16(number), net.JoinHostPort(host, port)
	return metadata
}
