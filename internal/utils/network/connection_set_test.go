package network

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestConnectionSetClosesIdleAndLateSockets(t *testing.T) {
	var set ConnectionSet
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		conn, peer := net.Pipe()
		defer peer.Close()
		workers.Add(1)
		go func() {
			defer workers.Done()
			set.Add(conn)
			_ = peer.SetReadDeadline(time.Now().Add(time.Second))
			_, err := peer.Read(make([]byte, 1))
			if err == nil {
				t.Error("expected closed socket")
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Error("socket leaked across cancellation")
			}
		}()
	}
	set.CloseAll()
	workers.Wait()
	set.CloseAll()
}
