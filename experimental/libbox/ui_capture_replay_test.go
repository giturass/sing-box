package libbox

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/experimental/httpdebug"
	M "github.com/sagernet/sing/common/metadata"
)

func TestUICaptureReplayTaskIsSingleUseAndCancellable(t *testing.T) {
	task := newUICaptureReplayTask(func() bool { return true },
		func(context.Context, net.Conn, M.Socksaddr, func(error)) { t.Error("an unknown record was routed") }, nil)
	if _, err := task.Replay("not-an-id", `{}`); err == nil {
		t.Fatal("an unknown record was replayed")
	}
	if _, err := task.Replay("not-an-id", `{}`); err == nil || err.Error() != "request replay task has already been used" {
		t.Fatalf("a task was reused: %v", err)
	}
	closed := newUICaptureReplayTask(func() bool { return true }, nil, nil)
	closed.Close()
	if _, err := closed.Replay("not-an-id", `{}`); err != context.Canceled {
		t.Fatalf("a closed task started: %v", err)
	}
	changed := newUICaptureReplayTask(func() bool { return false },
		func(context.Context, net.Conn, M.Socksaddr, func(error)) { t.Error("a replaced service was routed") }, nil)
	defer changed.Close()
	if _, err := changed.dial(context.Background(), "example.test:80"); err == nil {
		t.Fatal("a replay dialed through a replaced service")
	}
	if _, err := task.dial(httpdebug.WithoutProcessing(context.Background()), "example.test"); err == nil {
		t.Fatal("a destination without a port was dialed")
	}
}

func TestUICaptureReplayServiceCloseWaitsForRouting(t *testing.T) {
	server := &CommandServer{StartedService: daemon.NewStartedService(daemon.ServiceOptions{
		Context: context.Background(), LogMaxLines: 32,
	})}
	t.Cleanup(server.StartedService.Close)
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	releaseRouting := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseRouting)
	task := newUICaptureReplayTask(func() bool { return true },
		func(ctx context.Context, conn net.Conn, destination M.Socksaddr, onClose func(error)) {
			if !httpdebug.ProcessingDisabled(ctx) || destination.String() != "example.test:443" {
				t.Errorf("replay route context: disabled=%t destination=%s", httpdebug.ProcessingDisabled(ctx), destination)
			}
			close(entered)
			<-ctx.Done()
			close(cancelled)
			// Model a DNS/dial operation still unwinding after cancellation.
			<-release
			onClose(ctx.Err())
		}, nil)
	server.uiReplayTasks.add(task)
	conn, err := task.dial(context.Background(), "example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("replay did not enter routing")
	}
	closed := make(chan error, 1)
	go func() { closed <- server.CloseService() }()
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("close did not cancel the routed replay")
	}
	select {
	case err = <-closed:
		t.Fatalf("close returned before routing stopped: %v", err)
	case <-time.After(40 * time.Millisecond):
	}
	releaseRouting()
	select {
	case err = <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close did not finish after routing stopped")
	}
	server.uiReplayTasks.access.Lock()
	remaining := len(server.uiReplayTasks.tasks)
	server.uiReplayTasks.access.Unlock()
	if remaining != 0 {
		t.Fatal("a closed replay task stayed registered")
	}
	if _, err = task.dial(context.Background(), "example.test:443"); err == nil {
		t.Fatal("a closed task started another routed connection")
	}
}
