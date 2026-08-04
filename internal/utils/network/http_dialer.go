package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/sahmadiut/backhaul/config"
)

// HttpDialer establishes an HTTP(S) connection to the given address and path,
// performs a token-authenticated handshake, then hijacks the connection to
// return the raw net.Conn for tunneling. The initial HTTP request looks like
// normal HTTP traffic to firewalls/DPI.
func HttpDialer(ctx context.Context, addr string, edgeIP string, path string, timeout time.Duration, keepalive time.Duration, nodelay bool, token string, mode config.TransportType, retry int, SO_RCVBUF int, SO_SNDBUF int) (net.Conn, error) {
	var conn net.Conn
	var err error

	retries := retry           // Number of retries
	backoff := 1 * time.Second // Initial backoff duration

	for i := 0; i < retries; i++ {
		conn, err = attemptDialHTTP(ctx, addr, edgeIP, path, timeout, keepalive, nodelay, token, mode, SO_RCVBUF, SO_SNDBUF)
		if err == nil {
			return conn, nil
		}

		// If this is the last retry, return the error
		if i == retries-1 {
			break
		}

		time.Sleep(backoff)
		backoff *= 2 // Exponential backoff
	}

	return nil, err
}

func attemptDialHTTP(ctx context.Context, addr string, edgeIP string, path string, timeout time.Duration, keepalive time.Duration, nodelay bool, token string, mode config.TransportType, SO_RCVBUF int, SO_SNDBUF int) (net.Conn, error) {
	// Generate a random X-user-id
	randomUserID := rand.Int31()

	// List of diverse User-Agent strings
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 11_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 12; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:114.0) Gecko/20100101 Firefox/114.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:102.0) Gecko/20100101 Firefox/102.0",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 11_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.64",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 OPR/97.0.4719.63",
		"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
	}

	// Pick a random User-Agent
	randomUserAgent := userAgents[rand.Intn(len(userAgents))]

	// Handle edgeIP assignment
	dialAddr := addr
	if edgeIP != "" {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid address format, failed to parse: %w", err)
		}
		dialAddr = fmt.Sprintf("%s:%s", edgeIP, port)
	}

	// path generation for tunnel connections
	if path != "/channel" {
		path = fmt.Sprintf("%s/%s", path, strconv.Itoa(int(randomUserID)))
	}

	// Establish raw TCP connection
	tcpConn, err := TcpDialer(ctx, dialAddr, "", timeout, keepalive, nodelay, 1, SO_RCVBUF, SO_SNDBUF, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to dial TCP: %w", err)
	}

	var rawConn net.Conn = tcpConn

	// For HTTPS, wrap the connection with TLS
	if mode == config.HTTPS {
		host, _, _ := net.SplitHostPort(addr)
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true, // Skip server certificate verification
			ServerName:         host,
		}
		tlsConn := tls.Client(tcpConn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		rawConn = tlsConn
	}

	// Build the HTTP request manually to send over the raw connection
	// This makes the initial traffic look like normal HTTP to DPI
	scheme := "http"
	if mode == config.HTTPS {
		scheme = "https"
	}
	_ = scheme // used for documentation only

	httpReq := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Authorization: Bearer %s\r\n"+
		"X-User-Id: %d\r\n"+
		"User-Agent: %s\r\n"+
		"Connection: Upgrade\r\n"+
		"Upgrade: backhaul\r\n"+
		"\r\n",
		path, addr, token, randomUserID, randomUserAgent)

	// Send the HTTP request
	if _, err := rawConn.Write([]byte(httpReq)); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("failed to send HTTP request: %w", err)
	}

	// Read the HTTP response (we expect "HTTP/1.1 101" for successful hijack)
	buf := make([]byte, 4096)
	if err := rawConn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("failed to set read deadline: %w", err)
	}

	n, err := rawConn.Read(buf)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("failed to read HTTP response: %w", err)
	}

	response := string(buf[:n])

	// Check for 101 Switching Protocols (successful hijack)
	if len(response) < 12 || response[9:12] != "101" {
		rawConn.Close()
		return nil, fmt.Errorf("unexpected HTTP response: %s", response)
	}

	// Reset the deadline
	rawConn.SetReadDeadline(time.Time{})

	return rawConn, nil
}

// HttpListener wraps an HTTP server that hijacks connections and returns them
// through a channel. This is used by the server-side HTTP transport.
type HttpListener struct {
	connChan chan net.Conn
	server   *http.Server
}
