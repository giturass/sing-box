package httpdebug

import (
	"io"
	"sync/atomic"
)

// heldBody reads a paused message's body ahead of whoever forwards it. A body
// that is slow or too large to edit then pauses as a stream instead of keeping
// its message out of the paused list, and a request whose sender disappears is
// noticed: net/http reports a closed HTTP/1 connection only once the request
// body has been read to its end.
type heldBody struct {
	source io.ReadCloser
	stop   atomic.Bool
	// done closes when reading ahead ends; data and err are settled from then on.
	done chan struct{}
	// lost closes when the source failed before its end.
	lost chan struct{}
	data []byte
	err  error
}

func holdBody(source io.ReadCloser, limit int) *heldBody {
	b := &heldBody{source: source, done: make(chan struct{}), lost: make(chan struct{})}
	go func() {
		defer close(b.done)
		chunk := make([]byte, 32<<10)
		for len(b.data) <= limit && !b.stop.Load() {
			n, err := source.Read(chunk)
			b.data = append(b.data, chunk[:n]...)
			if err != nil {
				b.err = err
				if err != io.EOF {
					close(b.lost)
				}
				return
			}
		}
	}()
	return b
}

// Read replays what was read ahead and then continues on the source.
func (b *heldBody) Read(p []byte) (int, error) {
	b.stop.Store(true)
	<-b.done
	if len(b.data) > 0 {
		n := copy(p, b.data)
		b.data = b.data[n:]
		return n, nil
	}
	if b.err != nil {
		return 0, b.err
	}
	return b.source.Read(p)
}

func (b *heldBody) Close() error {
	b.stop.Store(true)
	return b.source.Close()
}
