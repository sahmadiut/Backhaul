package transport

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sahmadiut/backhaul/config"
	"github.com/sirupsen/logrus"
)

func TestHTTPClientDetectsSilentControlPeer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	s := &httpClientSession{HttpTransport: &HttpTransport{config: &HttpConfig{HeartbeatTimeout: 30 * time.Millisecond}, logger: logger}, ctx: ctx, controlChannel: conn}
	done := make(chan struct{})
	go func() { defer close(done); s.channelHandler() }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("silent control peer was not detected")
	}
}

func TestHTTPPoolRepairsClosedIdleSocketsAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var attempts atomic.Int32
	accepted := make(chan net.Conn, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		attempts.Add(1)
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: backhaul\r\nConnection: Upgrade\r\n\r\n")
		_ = rw.Flush()
		select {
		case accepted <- conn:
		case <-ctx.Done():
			conn.Close()
		}
	}))
	defer server.Close()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	s := &httpClientSession{
		HttpTransport: &HttpTransport{config: &HttpConfig{RemoteAddr: strings.TrimPrefix(server.URL, "http://"), Mode: config.HTTP, ConnPoolSize: 2, DialTimeOut: time.Second, KeepAlive: time.Second}, logger: logger},
		ctx:           ctx, cancel: cancel, poolWake: make(chan struct{}, 1),
	}
	stop := context.AfterFunc(ctx, s.connections.CloseAll)
	defer stop()
	s.workers.Add(1)
	go func() { defer s.workers.Done(); s.poolMaintainer() }()
	defer func() {
		cancel()
		s.connections.CloseAll()
		s.workers.Wait()
		for {
			select {
			case conn := <-accepted:
				conn.Close()
			default:
				return
			}
		}
	}()
	for cycle := 0; cycle < 3; cycle++ {
		var idle []net.Conn
		for i := 0; i < 2; i++ {
			select {
			case conn := <-accepted:
				idle = append(idle, conn)
			case <-time.After(3 * time.Second):
				t.Fatal("idle pool was not replenished")
			}
		}
		// No assignment/control signals are sent; failures must trigger repair.
		for _, conn := range idle {
			conn.Close()
		}
	}
	if got := attempts.Load(); got < 6 {
		t.Fatalf("only %d connections made", got)
	}
}

func TestHTTPRetryWaitHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if waitHTTPRetry(ctx, time.Hour) {
		t.Fatal("cancelled retry continued")
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancellation waited for retry interval")
	}
}
