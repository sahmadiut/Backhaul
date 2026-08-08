package handlers

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"

	"github.com/sahmadiut/backhaul/internal/web"
	"github.com/sirupsen/logrus"
)

// bufferPool provides reusable 64KB buffers for data transfer,
// reducing GC pressure under sustained load.
var bufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 64*1024) // 64K
		return &buf
	},
}

// A TLS Read returns at most one 16KB plaintext record. Using a larger buffer
// in that direction only increases per-connection memory retention.
var tlsReadBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 16*1024)
		return &buf
	},
}

func TCPConnectionHandler(ctx context.Context, proxyProtocol bool, from net.Conn, to net.Conn, logger *logrus.Logger, usage *web.Usage, remotePort int, sniffer bool) {
	done := make(chan struct{})

	// Write Proxy Protocol V2 Header
	if proxyProtocol {
		err := WriteProxyProtocol(from, to)
		if err != nil {
			logger.Error(err)
			from.Close()
			to.Close()
			return
		}
	}

	stopCancelWatcher := context.AfterFunc(ctx, func() {
		from.Close()
		to.Close()
	})
	defer stopCancelWatcher()

	go func() {
		defer close(done)
		transferData(from, to, logger, usage, remotePort, sniffer)
	}()

	transferData(to, from, logger, usage, remotePort, sniffer)

	select {
	case <-ctx.Done():
		from.Close()
		to.Close()
		return
	case <-done:
	}
}

// Using direct Read and Write for transferring data
func transferData(from net.Conn, to net.Conn, logger *logrus.Logger, usage *web.Usage, remotePort int, sniffer bool) {
	// On Linux, io.Copy between TCP sockets reaches net.TCPConn.ReadFrom and
	// uses splice(2), avoiding user-space copies and reusable buffer memory.
	if !sniffer && runtime.GOOS == "linux" {
		if isTCPConn(from) && isTCPConn(to) {
			written, err := io.Copy(to, from)
			if err != nil && !errors.Is(err, net.ErrClosed) {
				logger.Trace("unable to splice connection data: ", err)
			}
			logger.Tracef("spliced data: %d bytes", written)
			from.Close()
			to.Close()
			return
		}
	}

	pool := &bufferPool
	if _, ok := from.(*tls.Conn); ok {
		pool = &tlsReadBufferPool
	}
	bufPtr := pool.Get().(*[]byte)
	buf := *bufPtr
	defer pool.Put(bufPtr)

	for {
		// Read data from the source connection
		r, err := from.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				logger.Trace("reader stream closed or EOF received")
			} else {
				logger.Trace("unable to read from the connection: ", err)
			}
			from.Close()
			to.Close()
			return
		}

		totalWritten := 0
		for totalWritten < r {
			// Write data to the destination connection
			w, err := to.Write(buf[totalWritten:r])
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					logger.Trace("writer stream closed or EOF received")
				} else {
					logger.Trace("unable to write to the connection: ", err)
				}
				from.Close()
				to.Close()
				return

			}
			totalWritten += w
		}

		logger.Tracef("read data: %d bytes, written data: %d bytes", r, totalWritten)
		if sniffer {
			usage.AddOrUpdatePort(remotePort, uint64(totalWritten))
		}
	}

}

type connectionUnwrapper interface {
	Unwrap() net.Conn
}

func isTCPConn(conn net.Conn) bool {
	for {
		if _, ok := conn.(*net.TCPConn); ok {
			return true
		}
		unwrapper, ok := conn.(connectionUnwrapper)
		if !ok {
			return false
		}
		conn = unwrapper.Unwrap()
	}
}
