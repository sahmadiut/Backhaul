package network

import (
	"crypto/tls"
	"net"
	"sync"
)

// ConnectionSet owns all sockets in one tunnel generation, including idle and
// queued sockets that http.Server.Shutdown does not close after hijacking.
type ConnectionSet struct {
	mu          sync.Mutex
	closed      bool
	closeOnce   sync.Once
	connections map[net.Conn]struct{}
}

func (s *ConnectionSet) Add(conn net.Conn) bool {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		abortConnection(conn)
		return false
	}
	if s.connections == nil {
		s.connections = make(map[net.Conn]struct{})
	}
	s.connections[conn] = struct{}{}
	s.mu.Unlock()
	return true
}

func (s *ConnectionSet) Remove(conn net.Conn) {
	s.mu.Lock()
	delete(s.connections, conn)
	s.mu.Unlock()
}

func (s *ConnectionSet) Close(conn net.Conn) {
	s.Remove(conn)
	conn.Close()
}

func (s *ConnectionSet) CloseAll() {
	// Concurrent cleanup callers join the same close operation before returning.
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		connections := s.connections
		s.connections = nil
		s.mu.Unlock()
		for conn := range connections {
			abortConnection(conn)
		}
	})
}

func abortConnection(conn net.Conn) {
	// A failed generation is being aborted, not gracefully drained. Closing
	// the TCP socket avoids serial TLS close_notify waits on blackholed peers.
	for {
		if wrapped, ok := conn.(interface{ Unwrap() net.Conn }); ok {
			conn = wrapped.Unwrap()
			continue
		}
		if secure, ok := conn.(*tls.Conn); ok {
			conn = secure.NetConn()
			continue
		}
		break
	}
	conn.Close()
}
