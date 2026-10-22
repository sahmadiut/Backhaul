package transport

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sahmadiut/backhaul/config"
	client "github.com/sahmadiut/backhaul/internal/client/transport"
	"github.com/sahmadiut/backhaul/internal/utils"
	"github.com/sirupsen/logrus"
)

func quietHTTPLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return logger
}

func freeHTTPAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func httpTestCertificate(t *testing.T) (string, string) {
	t.Helper()
	ts := httptest.NewTLSServer(nil)
	cert := ts.TLS.Certificates[0]
	ts.Close()
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestHTTPAndHTTPSRecoverAfterRestart(t *testing.T) {
	for _, mode := range []config.TransportType{config.HTTP, config.HTTPS} {
		t.Run(string(mode), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			echo, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			var echoWorkers sync.WaitGroup
			echoWorkers.Add(1)
			go func() {
				defer echoWorkers.Done()
				for {
					conn, err := echo.Accept()
					if err != nil {
						return
					}
					echoWorkers.Add(1)
					go func() { defer echoWorkers.Done(); defer conn.Close(); _, _ = io.Copy(conn, conn) }()
				}
			}()
			tunnelAddr, localAddr := freeHTTPAddress(t), freeHTTPAddress(t)
			cfg := &HttpConfig{BindAddr: tunnelAddr, Token: "test", Mode: mode, ChannelSize: 32, Heartbeat: 50 * time.Millisecond, KeepAlive: time.Second, Nodelay: true, Ports: []string{localAddr + "=" + echo.Addr().String()}}
			if mode == config.HTTPS {
				cfg.TLSCertFile, cfg.TLSKeyFile = httpTestCertificate(t)
			}
			srv := NewHTTPServer(ctx, cfg, quietHTTPLogger())
			serverDone := make(chan struct{})
			go func() { defer close(serverDone); srv.run() }()
			cli := client.NewHTTPClient(ctx, &client.HttpConfig{RemoteAddr: tunnelAddr, Token: "test", Mode: mode, ConnPoolSize: 2, RetryInterval: 20 * time.Millisecond, DialTimeOut: time.Second, KeepAlive: time.Second, Nodelay: true, HeartbeatTimeout: time.Second}, quietHTTPLogger())
			cli.Start()
			t.Cleanup(func() {
				cancel()
				echo.Close()
				select {
				case <-serverDone:
				case <-time.After(5 * time.Second):
					t.Error("server workers did not shut down")
				}
				echoDone := make(chan struct{})
				go func() { echoWorkers.Wait(); close(echoDone) }()
				select {
				case <-echoDone:
				case <-time.After(5 * time.Second):
					t.Error("echo connections leaked")
				}
			})
			payload := bytes.Repeat([]byte("backhaul-http-recovery-"), 4096)
			connect := func() net.Conn {
				t.Helper()
				until := time.Now().Add(10 * time.Second)
				for time.Now().Before(until) {
					conn, err := net.DialTimeout("tcp", localAddr, 100*time.Millisecond)
					if err == nil {
						_ = conn.SetDeadline(time.Now().Add(time.Second))
						_, err = conn.Write(payload)
						got := make([]byte, len(payload))
						if err == nil {
							_, err = io.ReadFull(conn, got)
						}
						if err == nil && bytes.Equal(got, payload) {
							return conn
						}
						conn.Close()
					}
					time.Sleep(20 * time.Millisecond)
				}
				t.Fatal("tunnel did not become usable")
				return nil
			}
			for cycle := 0; cycle < 3; cycle++ {
				old := connect()
				if cycle%2 == 0 {
					srv.Restart()
				} else {
					cli.Restart()
				}
				_ = old.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, err := old.Read(make([]byte, 1))
				old.Close()
				if err == nil {
					t.Fatal("old stream survived restart")
				}
				if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					t.Fatal("old stream was not closed on restart")
				}
			}
			connect().Close()
		})
	}
}

func TestHTTPMissingHeartbeatCancelsSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	s := &httpServerSession{HttpTransport: &HttpTransport{config: &HttpConfig{Heartbeat: 20 * time.Millisecond}}, ctx: ctx, cancel: cancel, reqNewConnChan: make(chan struct{}, 1)}
	// Read heartbeats but never acknowledge: writes succeed, reads must time out.
	go io.Copy(io.Discard, peer)
	s.launch(func() { s.channelHandler(conn) })
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("missing heartbeats did not cancel session")
	}
	conn.Close()
	s.workers.Wait()
}

func TestHTTPPairingWriteHasDeadline(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	defer conn.Close()
	s := &httpServerSession{HttpTransport: &HttpTransport{logger: quietHTTPLogger()}, ctx: context.Background()}
	// Only 30ms remain in the local connection's three-second pairing budget.
	local := LocalTCPConn{remoteAddr: "8080", timeCreated: time.Now().Add(-2970 * time.Millisecond).UnixMilli()}
	done := make(chan bool, 1)
	go func() { done <- s.pairHTTPConnections(local, conn) }()
	select {
	case paired := <-done:
		if paired {
			t.Fatal("paired with a peer that never reads")
		}
	case <-time.After(time.Second):
		t.Fatal("pairing write blocked indefinitely")
	}
}

func TestHTTPHeartbeatAcknowledgementsKeepSessionAlive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	conn, peer := net.Pipe()
	defer peer.Close()
	s := &httpServerSession{HttpTransport: &HttpTransport{config: &HttpConfig{Heartbeat: 20 * time.Millisecond}}, ctx: ctx, cancel: cancel, reqNewConnChan: make(chan struct{}, 1)}
	go func() {
		for {
			msg, err := utils.ReceiveBinaryByte(peer)
			if err != nil {
				return
			}
			if err := utils.SendBinaryByte(peer, msg); err != nil {
				return
			}
		}
	}()
	s.launch(func() { s.channelHandler(conn) })
	select {
	case <-ctx.Done():
		t.Error("responsive peer was disconnected")
	case <-time.After(200 * time.Millisecond):
	}
	cancel()
	conn.Close()
	s.workers.Wait()
}
