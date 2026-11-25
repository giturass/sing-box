package libbox

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/httpdebug"
	M "github.com/sagernet/sing/common/metadata"
)

// A replay task owns one cancellable resend through this service instance. A
// reload or stop cancels it; the request never moves to a replacement instance.
type UICaptureReplayTask struct {
	ctx     context.Context
	cancel  context.CancelFunc
	routes  *uiRouteLifecycle
	dial    httpdebug.RewriteDialFunc
	roots   *x509.CertPool
	onClose func()
	used    atomic.Bool
}

// Creation shares uiCaptureLifecycle; service teardown holds it exclusively.
type uiReplayTaskSet struct {
	access sync.Mutex
	tasks  map[*UICaptureReplayTask]struct{}
}

func (s *uiReplayTaskSet) add(task *UICaptureReplayTask) {
	s.access.Lock()
	defer s.access.Unlock()
	if s.tasks == nil {
		s.tasks = make(map[*UICaptureReplayTask]struct{})
	}
	s.tasks[task] = struct{}{}
	task.onClose = func() {
		s.access.Lock()
		delete(s.tasks, task)
		s.access.Unlock()
	}
}

func (s *uiReplayTaskSet) close() {
	s.access.Lock()
	tasks := make([]*UICaptureReplayTask, 0, len(s.tasks))
	for task := range s.tasks {
		tasks = append(tasks, task)
	}
	s.access.Unlock()
	for _, task := range tasks {
		task.Close()
	}
	for _, task := range tasks {
		// DNS/dial setup must finish before its service instance is closed.
		task.routes.wait()
	}
}

// NewUICaptureReplayTask routes with the `b-box-replay` inbound context and the
// instance's certificate store. It opens no listener and never dials directly.
func (s *CommandServer) NewUICaptureReplayTask() (*UICaptureReplayTask, error) {
	if !uiCaptureLifecycle.TryRLock() {
		return nil, errors.New("local service is changing during request replay")
	}
	defer uiCaptureLifecycle.RUnlock()
	instance := s.Instance()
	if instance == nil {
		return nil, errors.New("request replay needs the running local service")
	}
	task := newUICaptureReplayTask(func() bool { return s.Instance() == instance },
		func(ctx context.Context, conn net.Conn, destination M.Socksaddr, onClose func(error)) {
			metadata := adapter.InboundContext{Inbound: "b-box-replay", Network: "tcp", Source: M.ParseSocksaddr("127.0.0.1:0"), Destination: destination}
			instance.Box().Router().RouteConnectionEx(adapter.WithContext(ctx, &metadata), conn, metadata, onClose)
		}, instance.UIRootPool())
	s.uiReplayTasks.add(task)
	return task, nil
}

func newUICaptureReplayTask(current func() bool, route func(context.Context, net.Conn, M.Socksaddr, func(error)), roots *x509.CertPool) *UICaptureReplayTask {
	ctx, cancel := context.WithCancel(context.Background())
	task := &UICaptureReplayTask{ctx: ctx, cancel: cancel, routes: newUIRouteLifecycle(ctx), roots: roots}
	task.dial = func(ctx context.Context, address string) (net.Conn, error) {
		if !current() {
			return nil, errors.New("local service changed during request replay")
		}
		destination := M.ParseSocksaddr(address)
		if !destination.IsValid() || destination.Port == 0 {
			return nil, errors.New("invalid replay destination")
		}
		// The replay is recorded by its own task, never intercepted again.
		return task.routes.route(httpdebug.WithoutProcessing(ctx), func(ctx context.Context, conn net.Conn, onClose func(error)) {
			route(ctx, conn, destination, onClose)
		})
	}
	return task
}

// Replay returns the JSON result once the response has ended. The new record
// exists whenever a result is returned, including for a failed send.
func (t *UICaptureReplayTask) Replay(id, optionsJSON string) (string, error) {
	if t == nil || !t.used.CompareAndSwap(false, true) {
		return "", errors.New("request replay task has already been used")
	}
	if err := t.ctx.Err(); err != nil {
		return "", err
	}
	store, err := httpdebug.Saved()
	if err != nil {
		return "", err
	}
	result, err := store.Replay(t.ctx, id, optionsJSON, t.dial, t.roots)
	if err != nil {
		return "", err
	}
	return captureJSON(result)
}

func (t *UICaptureReplayTask) Close() {
	if t == nil {
		return
	}
	t.cancel()
	t.routes.close()
	if t.onClose != nil {
		t.onClose()
	}
}
