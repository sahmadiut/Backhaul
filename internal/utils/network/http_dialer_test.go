package network

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sahmadiut/backhaul/config"
)

const testUpgradeResponse = "HTTP/1.1 101 Switching Protocols\r\n" +
	"Upgrade: backhaul\r\n" +
	"Connection: Upgrade\r\n\r\n"

func TestHTTPDialCancellationIncludesDNS(t *testing.T) {
	previous := net.DefaultResolver
	started := make(chan struct{})
	var once sync.Once
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		once.Do(func() { close(started) })
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	defer func() { net.DefaultResolver = previous }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		conn, err := HttpDialer(ctx, "backhaul-cancel.invalid:443", "", "/channel", 10*time.Second, time.Second, true, "test", config.HTTP, 1, 0, 0)
		if conn != nil {
			conn.Close()
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("DNS lookup did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled DNS dial succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("DNS lookup outlived dial cancellation")
	}
}

func TestBuildHTTPUpgradeRequest(t *testing.T) {
	request := string(buildHTTPUpgradeRequest("example.com:443", "/tunnel", "secret", 42, "test-agent"))
	want := "GET /tunnel/42 HTTP/1.1\r\n" +
		"Host: example.com:443\r\n" +
		"Authorization: Bearer secret\r\n" +
		"X-User-Id: 42\r\n" +
		"User-Agent: test-agent\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: backhaul\r\n\r\n"
	if request != want {
		t.Fatalf("unexpected request:\n%s\nwant:\n%s", request, want)
	}

	channelRequest := string(buildHTTPUpgradeRequest("example.com:443", "/channel", "secret", 42, "test-agent"))
	if !strings.HasPrefix(channelRequest, "GET /channel HTTP/1.1\r\n") {
		t.Fatalf("channel path received a tunnel suffix: %q", channelRequest)
	}
}

func TestHTTPUpgradeCancellationInterruptsStalledPeer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	done := make(chan error, 1)
	go func() {
		conn, err := HttpDialer(ctx, listener.Addr().String(), "", "/channel", 0, time.Second, true, "test", config.HTTP, 1, 0, 0)
		if conn != nil {
			conn.Close()
		}
		done <- err
	}()
	select {
	case conn := <-accepted:
		defer conn.Close()
	case <-time.After(time.Second):
		t.Fatal("dial did not connect")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled upgrade succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP handshake ignored cancellation")
	}
}

func TestReadHTTPUpgradeResponseHandlesFragmentation(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	serverDone := make(chan error, 1)
	go func() {
		for _, fragment := range []string{"HTTP/1.1 101 Switch", "ing Protocols\r\nUpgrade: backhaul\r\n", "Connection: Upgrade\r\n\r\n"} {
			if _, err := io.WriteString(server, fragment); err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
	}()

	client.SetDeadline(time.Now().Add(time.Second))
	upgraded, err := readHTTPUpgradeResponse(client)
	if err != nil {
		t.Fatal(err)
	}
	if upgraded != client {
		t.Fatal("fragmented response without payload unexpectedly wrapped the connection")
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestReadHTTPUpgradeResponsePreservesCoalescedPayload(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	payload := []byte{0x02, 0x00, 0x05, '8', '0', '8', '0'}
	go func() {
		_, _ = server.Write(append([]byte(testUpgradeResponse), payload...))
	}()

	client.SetDeadline(time.Now().Add(time.Second))
	upgraded, err := readHTTPUpgradeResponse(client)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(upgraded, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("coalesced payload = %v, want %v", got, payload)
	}
}

func TestReadHTTPUpgradeResponseRejectsNonUpgrade(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_, _ = io.WriteString(server, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
	}()
	client.SetDeadline(time.Now().Add(time.Second))
	if _, err := readHTTPUpgradeResponse(client); err == nil {
		t.Fatal("expected a non-101 response error")
	}
}

func BenchmarkBuildHTTPUpgradeRequest(b *testing.B) {
	b.Run("allocated", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = buildHTTPUpgradeRequest("example.com:443", "/tunnel", "secret", 123456789, userAgents[0])
		}
	})
	b.Run("pooled", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			requestPtr := httpRequestPool.Get().(*[]byte)
			request := appendHTTPUpgradeRequest((*requestPtr)[:0], "example.com:443", "/tunnel", "secret", 123456789, userAgents[0])
			releaseHTTPRequest(requestPtr, request)
		}
	})
}
