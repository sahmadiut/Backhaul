package handlers

import (
	"crypto/tls"
	"io"
	"net"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
)

type relayBenchmarkSource struct {
	net.Conn
	remaining int
	maxBuffer int
}

func (c *relayBenchmarkSource) Read(p []byte) (int, error) {
	if len(p) > c.maxBuffer {
		c.maxBuffer = len(p)
	}
	if c.remaining == 0 {
		return 0, io.EOF
	}
	n := min(len(p), c.remaining)
	clear(p[:n])
	c.remaining -= n
	return n, nil
}
func (c *relayBenchmarkSource) Close() error { return nil }

// Measures the local-to-TLS relay with real TLS encryption over an in-memory
// socket. This is a CPU/buffer benchmark, not WAN or Linux splice throughput.
func BenchmarkHTTPSRelay(b *testing.B) {
	fixture := httptest.NewTLSServer(nil)
	serverConfig := fixture.TLS.Clone()
	fixture.Close()
	left, right := net.Pipe()
	client := tls.Client(left, &tls.Config{InsecureSkipVerify: true})
	server := tls.Server(right, serverConfig)
	done := make(chan int64, 1)
	go func() { n, _ := io.Copy(io.Discard, server); server.Close(); done <- n }()
	if err := client.Handshake(); err != nil {
		b.Fatal(err)
	}
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	source := &relayBenchmarkSource{remaining: b.N * 65536}
	b.SetBytes(65536)
	b.ReportAllocs()
	b.ResetTimer()
	transferData(source, client, logger, nil, 0, false)
	b.StopTimer()
	if got := <-done; got != int64(b.N)*65536 {
		b.Fatalf("relay lost bytes: %d", got)
	}
	b.ReportMetric(float64(source.maxBuffer), "buffer-B")
}
