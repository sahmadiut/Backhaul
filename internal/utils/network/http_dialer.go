package network

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/sahmadiut/backhaul/config"
)

const maxHTTPUpgradeResponseSize = 4 * 1024
const maxPooledHTTPRequestSize = 4 * 1024

var (
	// TLS session resumption avoids a full public-key handshake for every
	// connection added to the HTTPS tunnel pool.
	httpTLSSessionCache = tls.NewLRUClientSessionCache(256)
	httpTLSConfigs      sync.Map // map[string]*tls.Config, keyed by server name
	httpRequestPool     = sync.Pool{New: func() interface{} {
		request := make([]byte, 0, 512)
		return &request
	}}
	httpResponsePool = sync.Pool{New: func() interface{} {
		response := make([]byte, maxHTTPUpgradeResponseSize)
		return &response
	}}
)

// userAgents is allocated once at package level to avoid per-dial allocation.
var userAgents = []string{
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

// HttpDialer establishes an HTTP(S) connection to the given address and path,
// performs a token-authenticated handshake, then hijacks the connection to
// return the raw net.Conn for tunneling. The initial HTTP request looks like
// normal HTTP traffic to firewalls/DPI.
func HttpDialer(ctx context.Context, addr string, edgeIP string, path string, timeout time.Duration, keepalive time.Duration, nodelay bool, token string, mode config.TransportType, retry int, SO_RCVBUF int, SO_SNDBUF int) (net.Conn, error) {
	var err error
	backoff := time.Second

	for i := 0; i < retry; i++ {
		var conn net.Conn
		conn, err = attemptDialHTTP(ctx, addr, edgeIP, path, timeout, keepalive, nodelay, token, mode, SO_RCVBUF, SO_SNDBUF)
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if i == retry-1 {
			break
		}

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
		backoff *= 2
	}

	return nil, err
}

func attemptDialHTTP(ctx context.Context, addr string, edgeIP string, path string, timeout time.Duration, keepalive time.Duration, nodelay bool, token string, mode config.TransportType, SO_RCVBUF int, SO_SNDBUF int) (net.Conn, error) {
	randomUserID := rand.Int31()
	randomUserAgent := userAgents[rand.Intn(len(userAgents))]

	dialAddr := addr
	var serverName string
	if edgeIP != "" || mode == config.HTTPS {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid address format, failed to parse: %w", err)
		}
		serverName = host
		if edgeIP != "" {
			dialAddr = net.JoinHostPort(edgeIP, port)
		}
	}

	tcpConn, err := TcpDialer(ctx, dialAddr, "", timeout, keepalive, nodelay, 1, SO_RCVBUF, SO_SNDBUF, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to dial TCP: %w", err)
	}

	var rawConn net.Conn = tcpConn
	closeWithError := func(format string, args ...interface{}) (net.Conn, error) {
		_ = rawConn.Close()
		return nil, fmt.Errorf(format, args...)
	}

	// The TCP dial timeout does not protect against a peer that accepts and stalls.
	if timeout > 0 {
		if err := rawConn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return closeWithError("failed to set HTTP handshake deadline: %w", err)
		}
	}

	if mode == config.HTTPS {
		tlsConn := tls.Client(tcpConn, httpTLSConfig(serverName))
		rawConn = tlsConn
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return closeWithError("TLS handshake failed: %w", err)
		}
	}

	// Build the HTTP request manually to send over the raw connection
	// This makes the initial traffic look like normal HTTP to DPI
	requestPtr := httpRequestPool.Get().(*[]byte)
	request := appendHTTPUpgradeRequest((*requestPtr)[:0], addr, path, token, randomUserID, randomUserAgent)
	if err := writeAll(rawConn, request); err != nil {
		releaseHTTPRequest(requestPtr, request)
		return closeWithError("failed to send HTTP request: %w", err)
	}
	releaseHTTPRequest(requestPtr, request)

	// Read the complete HTTP response while preserving coalesced tunnel bytes.
	upgradedConn, err := readHTTPUpgradeResponse(rawConn)
	if err != nil {
		return closeWithError("failed to read HTTP upgrade response: %w", err)
	}
	if err := upgradedConn.SetDeadline(time.Time{}); err != nil {
		_ = upgradedConn.Close()
		return nil, fmt.Errorf("failed to clear HTTP handshake deadline: %w", err)
	}

	return upgradedConn, nil
}

func httpTLSConfig(serverName string) *tls.Config {
	if configValue, ok := httpTLSConfigs.Load(serverName); ok {
		return configValue.(*tls.Config)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // The transport intentionally supports self-signed certificates.
		ServerName:         serverName,
		ClientSessionCache: httpTLSSessionCache,
	}
	configValue, _ := httpTLSConfigs.LoadOrStore(serverName, tlsConfig)
	return configValue.(*tls.Config)
}

func buildHTTPUpgradeRequest(addr, path, token string, userID int32, userAgent string) []byte {
	request := make([]byte, 0, 192+len(addr)+len(path)+len(token)+len(userAgent))
	return appendHTTPUpgradeRequest(request, addr, path, token, userID, userAgent)
}

func appendHTTPUpgradeRequest(request []byte, addr, path, token string, userID int32, userAgent string) []byte {
	request = append(request, "GET "...)
	request = append(request, path...)
	if path != "/channel" {
		request = append(request, '/')
		request = strconv.AppendInt(request, int64(userID), 10)
	}
	request = append(request, " HTTP/1.1\r\nHost: "...)
	request = append(request, addr...)
	request = append(request, "\r\nAuthorization: Bearer "...)
	request = append(request, token...)
	request = append(request, "\r\nX-User-Id: "...)
	request = strconv.AppendInt(request, int64(userID), 10)
	request = append(request, "\r\nUser-Agent: "...)
	request = append(request, userAgent...)
	request = append(request, "\r\nConnection: Upgrade\r\nUpgrade: backhaul\r\n\r\n"...)
	return request
}

func releaseHTTPRequest(requestPtr *[]byte, request []byte) {
	if cap(request) > maxPooledHTTPRequestSize {
		// append allocated a larger backing array; retain the original small
		// pooled buffer and let the oversized request be reclaimed normally.
		*requestPtr = (*requestPtr)[:0]
		httpRequestPool.Put(requestPtr)
		return
	}
	*requestPtr = request[:0]
	httpRequestPool.Put(requestPtr)
}

func writeAll(conn net.Conn, payload []byte) error {
	for len(payload) > 0 {
		n, err := conn.Write(payload)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func readHTTPUpgradeResponse(conn net.Conn) (net.Conn, error) {
	responsePtr := httpResponsePool.Get().(*[]byte)
	response := *responsePtr
	defer httpResponsePool.Put(responsePtr)
	total := 0

	for total < len(response) {
		n, err := conn.Read(response[total:])
		total += n
		if headerIndex := bytes.Index(response[:total], []byte("\r\n\r\n")); headerIndex >= 0 {
			headerEnd := headerIndex + 4
			if total < 12 || !bytes.Equal(response[9:12], []byte("101")) {
				return nil, fmt.Errorf("unexpected HTTP response: %.512s", response[:total])
			}
			if headerEnd == total {
				return conn, nil
			}

			// A fast server can send the first tunnel message in the same packet as
			// the 101 response. Replay it instead of silently discarding it.
			prefix := append([]byte(nil), response[headerEnd:total]...)
			return &prefixedConn{Conn: conn, prefix: prefix}, nil
		}
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, io.ErrNoProgress
		}
	}

	return nil, fmt.Errorf("HTTP upgrade response exceeds %d bytes", len(response))
}

// prefixedConn replays bytes read past the HTTP header boundary. Its io.Copy
// methods preserve optimized methods on the underlying connection afterward.
type prefixedConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixedConn) Unwrap() net.Conn {
	return c.Conn
}

func (c *prefixedConn) Read(payload []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(payload, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(payload)
}

func (c *prefixedConn) WriteTo(dst io.Writer) (int64, error) {
	var written int64
	if len(c.prefix) > 0 {
		n, err := dst.Write(c.prefix)
		written += int64(n)
		c.prefix = c.prefix[n:]
		if err != nil {
			return written, err
		}
		if len(c.prefix) > 0 {
			return written, io.ErrShortWrite
		}
	}
	if writerTo, ok := c.Conn.(io.WriterTo); ok {
		n, err := writerTo.WriteTo(dst)
		return written + n, err
	}
	n, err := io.Copy(dst, readerOnly{Reader: c.Conn})
	return written + n, err
}

func (c *prefixedConn) ReadFrom(src io.Reader) (int64, error) {
	if readerFrom, ok := c.Conn.(io.ReaderFrom); ok {
		return readerFrom.ReadFrom(src)
	}
	return io.Copy(writerOnly{Writer: c.Conn}, src)
}

type readerOnly struct{ io.Reader }
type writerOnly struct{ io.Writer }

// HttpListener wraps an HTTP server that hijacks connections and returns them
// through a channel. This is used by the server-side HTTP transport.
type HttpListener struct {
	connChan chan net.Conn
	server   *http.Server
}
