package handlers

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

type finalPayloadConn struct {
	net.Conn
	payload   []byte
	output    bytes.Buffer
	zeroWrite bool
}

func (c *finalPayloadConn) Read(p []byte) (int, error) {
	n := copy(p, c.payload)
	c.payload = c.payload[n:]
	if len(c.payload) == 0 {
		return n, io.EOF
	}
	return n, nil
}
func (c *finalPayloadConn) Write(p []byte) (int, error) {
	if c.zeroWrite {
		return 0, nil
	}
	return c.output.Write(p)
}
func (c *finalPayloadConn) Close() error { return nil }

func TestTransferPreservesPayloadReturnedWithEOF(t *testing.T) {
	src := &finalPayloadConn{payload: []byte("final tunnel bytes")}
	dst := &finalPayloadConn{}
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	transferData(src, dst, logger, nil, 0, false)
	if dst.output.String() != "final tunnel bytes" {
		t.Fatalf("final payload lost: %q", dst.output.String())
	}
}

func TestTransferStopsOnZeroWrite(t *testing.T) {
	src := &finalPayloadConn{payload: []byte("payload")}
	dst := &finalPayloadConn{zeroWrite: true}
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	done := make(chan struct{})
	go func() { defer close(done); transferData(src, dst, logger, nil, 0, false) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("zero-progress write spun forever")
	}
}

type wrappedTLSConn struct{ net.Conn }

func (c wrappedTLSConn) Unwrap() net.Conn { return c.Conn }

func TestWrappedHTTPSTunnelUsesTLSBuffer(t *testing.T) {
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	secure := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if !isTLSConn(wrappedTLSConn{secure}) {
		t.Fatal("HTTP upgrade wrapper hid TLS connection")
	}
	if isTLSConn(conn) {
		t.Fatal("plain connection classified as TLS")
	}
}
