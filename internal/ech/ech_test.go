package ech

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
)

func TestECHHandshake(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := Generate(dir, "tunnel.example.com", "public.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := Generate(dir, "tunnel.example.com", "public.example.com"); err == nil {
		t.Fatal("overwrote existing keys")
	}
	server, err := (&Server{Enabled: true, KeyFile: filepath.Join(dir, "ech-key.json")}).TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	server.Certificates = []tls.Certificate{cert}
	options := &Client{Enabled: true, ConfigFile: filepath.Join(dir, "ech-config.txt"), CAFile: filepath.Join(dir, "cert.pem")}
	for _, tc := range []struct {
		name    string
		keys    bool
		trust   bool
		success bool
	}{{"accepted", true, true, true}, {"rejected", false, true, false}, {"untrusted", true, false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := options.TLSConfig(context.Background(), "tunnel.example.com")
			if err != nil {
				t.Fatal(err)
			}
			if !tc.trust {
				client.RootCAs = nil
			}
			sc := server.Clone()
			if !tc.keys {
				sc.EncryptedClientHelloKeys = nil
			}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			done := make(chan error, 1)
			go func() {
				c, e := ln.Accept()
				if e != nil {
					done <- e
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				s := tls.Server(c, sc)
				e = s.Handshake()
				if e == nil && tc.success && !s.ConnectionState().ECHAccepted {
					t.Error("server did not accept ECH")
				}
				done <- e
			}()
			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			conn := tls.Client(c, client)
			err = conn.Handshake()
			if (err == nil) != tc.success {
				t.Fatalf("handshake: %v", err)
			}
			if err == nil && !conn.ConnectionState().ECHAccepted {
				t.Fatal("ECH not accepted")
			}
			c.Close()
			<-done
		})
	}
}

func TestOptions(t *testing.T) {
	var cfg struct{ Client Client }
	if _, err := toml.Decode("[client]\nech=true\nech_config='test'", &cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.Client.Enabled || cfg.Client.ConfigFile != "test" {
		t.Fatal("TOML options lost")
	}
	if v, e := (&Client{}).TLSConfig(context.Background(), "example.com"); v != nil || e != nil {
		t.Fatal("disabled changed TLS")
	}
	if _, e := (&Client{Enabled: true, ConfigFile: "missing"}).TLSConfig(context.Background(), "example.com"); e == nil {
		t.Fatal("missing config accepted")
	}
}

func TestDiscovery(t *testing.T) {
	// Use the test server's trusted transport without changing production TLS verification.
	old := http.DefaultTransport
	defer func() { http.DefaultTransport = old }()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") != "HTTPS" || r.URL.Query().Get("name") != "tunnel.example.com" {
			t.Error("wrong query")
		}
		json.NewEncoder(w).Encode(map[string]any{"Status": 0, "Answer": []any{map[string]any{"Type": 65, "Data": "1 . alpn=\"http/1.1\" ech=\"AAH/\""}}})
	}))
	defer server.Close()
	http.DefaultTransport = server.Client().Transport
	got, err := discover(context.Background(), "tunnel.example.com", server.URL)
	if err != nil || len(got) != 3 {
		t.Fatalf("discover: %x %v", got, err)
	}
	if _, err = discover(context.Background(), "example.com", "http://dns.example.com"); err == nil {
		t.Fatal("plaintext discovery allowed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = discover(ctx, "example.com", server.URL); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestInvalidFiles(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config")
	os.WriteFile(p, []byte("bad"), 0600)
	if _, err := (&Client{Enabled: true, ConfigFile: p}).TLSConfig(context.Background(), "example.com"); err == nil {
		t.Fatal("invalid list allowed")
	}
	if _, err := (&Server{Enabled: true, KeyFile: p}).TLSConfig(); err == nil {
		t.Fatal("invalid key allowed")
	}
}
