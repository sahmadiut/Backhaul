package ech

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Client is opt-in. A nil TLS configuration preserves the legacy dialer.
type Client struct {
	Enabled    bool   `toml:"ech"`
	ConfigFile string `toml:"ech_config"`
	CAFile     string `toml:"ech_ca"`
	DoHURL     string `toml:"ech_doh"`
	mu         sync.Mutex
	cached     []byte
	expires    time.Time
}

type Server struct {
	Enabled bool   `toml:"ech"`
	KeyFile string `toml:"ech_key"`
}

type keyFile struct{ Config, PrivateKey []byte }

func (s *Server) TLSConfig() (*tls.Config, error) {
	if s == nil || !s.Enabled {
		return nil, nil
	}
	b, err := os.ReadFile(s.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("read ech_key: %w", err)
	}
	var key keyFile
	if err = json.Unmarshal(b, &key); err != nil {
		return nil, fmt.Errorf("parse ech_key: %w", err)
	}
	if len(key.PrivateKey) != 32 || len(key.Config) < 4 {
		return nil, fmt.Errorf("invalid ECH key file; use -ech-generate")
	}
	return &tls.Config{EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{Config: key.Config, PrivateKey: key.PrivateKey, SendAsRetry: true}}}, nil
}

func (c *Client) TLSConfig(ctx context.Context, name string) (*tls.Config, error) {
	if c == nil || !c.Enabled {
		return nil, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var list []byte
	var err error
	if c.ConfigFile != "" {
		var b []byte
		b, err = os.ReadFile(c.ConfigFile)
		if err == nil {
			list, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		}
	} else if time.Now().Before(c.expires) {
		list = c.cached
	} else {
		list, err = discover(ctx, name, c.DoHURL)
		if err == nil {
			c.cached = list
			c.expires = time.Now().Add(time.Minute)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("ECH configuration: %w", err)
	}
	if len(list) < 6 || int(binary.BigEndian.Uint16(list)) != len(list)-2 {
		return nil, fmt.Errorf("invalid ECHConfigList")
	}
	cfg := &tls.Config{ServerName: name, MinVersion: tls.VersionTLS13, EncryptedClientHelloConfigList: list}
	if c.CAFile != "" {
		b, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, err
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("ech_ca contains no certificates")
		}
		cfg.RootCAs = roots
	}
	// No insecure verification, plaintext fallback, or shared legacy session cache.
	return cfg, nil
}

var echParam = regexp.MustCompile(`(?:^|\s)ech="?([A-Za-z0-9+/=]+)"?(?:\s|$)`)

func discover(ctx context.Context, name, endpoint string) ([]byte, error) {
	if endpoint == "" {
		endpoint = "https://cloudflare-dns.com/dns-query"
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("ech_doh must be an HTTPS DNS JSON endpoint")
	}
	q := u.Query()
	q.Set("name", name)
	q.Set("type", "HTTPS")
	u.RawQuery = q.Encode()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("DoH returned HTTP %d", resp.StatusCode)
	}
	var answer struct {
		Status int
		Answer []struct {
			Type int
			Data string
		}
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&answer); err != nil {
		return nil, err
	}
	if answer.Status != 0 {
		return nil, fmt.Errorf("DoH DNS status %d", answer.Status)
	}
	for _, rr := range answer.Answer {
		if rr.Type != 65 {
			continue
		}
		match := echParam.FindStringSubmatch(rr.Data)
		if len(match) > 1 {
			return base64.StdEncoding.DecodeString(match[1])
		}
	}
	return nil, fmt.Errorf("no ECH HTTPS record for %s; enable ECH at your CDN or set ech_config for a direct server", name)
}
