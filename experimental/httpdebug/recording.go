package httpdebug

import "net/http"

// Recording changes at HTTP request/TCP stream boundaries. Existing transports,
// TLS handshakes, rewrites and cron jobs belong to the service, not a recording.
func (e *Engine) beginRecording(metadata Metadata, request *http.Request) string {
	return e.beginRecord(metadata, request, false)
}

// A brief record covers one stream message and is written when it finishes.
func (e *Engine) beginRecord(metadata Metadata, request *http.Request, brief bool) string {
	e.mu.Lock()
	config := e.recording.Load()
	if e.closed || config == nil || !config.matches(metadata) {
		e.mu.Unlock()
		return ""
	}
	record := e.store.add(metadata, request, config.BodyLimit, brief)
	e.mu.Unlock()
	if record == nil {
		return ""
	}
	e.store.save(record)
	return record.ID
}

func (e *Engine) stopRecording() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.recording.Swap(nil) == nil {
		return
	}
	// Freeze retained prefixes immediately. A later EOF or response must not
	// make a partial record look complete, or append data after the user stops.
	e.store.stopRecording()
}

func (s *Store) stopRecording() {
	s.mu.Lock()
	stopped := make([]*Exchange, 0)
	for _, record := range s.records {
		if record.finishing || record.Complete {
			continue
		}
		appendRecordNote(record, "Recording stopped; retained data may be incomplete; connection continues")
		s.finishLocked(record)
		stopped = append(stopped, record)
	}
	s.mu.Unlock()
	for _, record := range stopped {
		s.save(record)
	}
}
