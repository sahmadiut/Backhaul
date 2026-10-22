package transport

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sahmadiut/backhaul/config"
	"github.com/sahmadiut/backhaul/internal/ech"
	"github.com/sahmadiut/backhaul/internal/utils"
	"github.com/sahmadiut/backhaul/internal/utils/handlers"
	"github.com/sahmadiut/backhaul/internal/utils/network"
	"github.com/sahmadiut/backhaul/internal/web"

	"github.com/sirupsen/logrus"
)

// HttpTransport supervises independent runs; a cancelled run is never reused.
type HttpTransport struct {
	config       *HttpConfig
	parentctx    context.Context
	logger       *logrus.Logger
	usageMonitor *web.Usage
	startOnce    sync.Once
	restartMutex sync.Mutex
	cancel       context.CancelFunc
}

type httpClientSession struct {
	*HttpTransport
	ctx             context.Context
	cancel          context.CancelFunc
	controlChannel  net.Conn
	connections     network.ConnectionSet
	workers         sync.WaitGroup
	poolConnections int32 // includes in-flight dials
	loadConnections int32
	poolWake        chan struct{}
}

type HttpConfig struct {
	ECH              *ech.Client
	RemoteAddr       string
	Token            string
	SnifferLog       string
	TunnelStatus     string
	Nodelay          bool
	Sniffer          bool
	KeepAlive        time.Duration
	RetryInterval    time.Duration
	HeartbeatTimeout time.Duration
	DialTimeOut      time.Duration
	ConnPoolSize     int
	WebPort          int
	Mode             config.TransportType
	AggressivePool   bool
	EdgeIP           string
}

func NewHTTPClient(parentCtx context.Context, cfg *HttpConfig, logger *logrus.Logger) *HttpTransport {
	return &HttpTransport{
		config: cfg, parentctx: parentCtx, logger: logger,
		usageMonitor: web.NewDataStore(fmt.Sprintf(":%v", cfg.WebPort), parentCtx, cfg.SnifferLog, cfg.Sniffer, &cfg.TunnelStatus, logger),
	}
}

func (c *HttpTransport) Start() {
	c.startOnce.Do(func() {
		if c.config.WebPort > 0 {
			go c.usageMonitor.Monitor()
		}
		go c.run()
	})
}

func (c *HttpTransport) Restart() {
	c.restartMutex.Lock()
	defer c.restartMutex.Unlock()
	if c.cancel != nil {
		c.cancel()
	}
}

func (c *HttpTransport) run() {
	for c.parentctx.Err() == nil {
		ctx, cancel := context.WithCancel(c.parentctx)
		session := &httpClientSession{HttpTransport: c, ctx: ctx, cancel: cancel, poolWake: make(chan struct{}, 1)}
		c.restartMutex.Lock()
		c.cancel = cancel
		c.restartMutex.Unlock()
		c.usageMonitor.SetTunnelStatus(fmt.Sprintf("Disconnected (%s)", c.config.Mode))
		stop := context.AfterFunc(ctx, session.connections.CloseAll)
		session.channelDialer()
		cancel()
		session.connections.CloseAll()
		session.workers.Wait()
		stop()
		c.usageMonitor.SetTunnelStatus(fmt.Sprintf("Disconnected (%s)", c.config.Mode))
		if !waitHTTPRetry(c.parentctx, c.config.RetryInterval) {
			return
		}
	}
}

func waitHTTPRetry(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		delay = time.Second
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return ctx.Err() == nil
	}
}

func (c *httpClientSession) channelDialer() {
	for c.ctx.Err() == nil {
		conn, err := network.HttpDialer(c.ctx, c.config.RemoteAddr, c.config.EdgeIP, "/channel", c.config.DialTimeOut, c.config.KeepAlive, true, c.config.Token, c.config.Mode, 3, 0, 0, c.config.ECH)
		if err != nil {
			if c.ctx.Err() != nil {
				return
			}
			c.logger.Errorf("control channel dialer: %v", err)
			if !waitHTTPRetry(c.ctx, c.config.RetryInterval) {
				return
			}
			continue
		}
		if !c.connections.Add(conn) {
			return
		}
		c.controlChannel = conn
		c.usageMonitor.SetTunnelStatus(fmt.Sprintf("Connected (%s)", c.config.Mode))
		c.workers.Add(1)
		go func() { defer c.workers.Done(); c.poolMaintainer() }()
		c.channelHandler()
		return
	}
}

func (c *httpClientSession) poolMaintainer() {
	base := c.config.ConnPoolSize
	if base < 1 {
		base = 1
	}
	target, maximum := base, base*4
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	loadTicker := time.NewTicker(10 * time.Second)
	defer loadTicker.Stop()
	fill := func() {
		for c.ctx.Err() == nil && int(atomic.LoadInt32(&c.poolConnections)) < target {
			atomic.AddInt32(&c.poolConnections, 1)
			c.workers.Add(1)
			go func() { defer c.workers.Done(); c.tunnelDialer() }()
		}
	}
	fill()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C: // Repair failed dials/idle sockets even without a server request.
		case <-c.poolWake:
		case <-loadTicker.C:
			load := int(atomic.SwapInt32(&c.loadConnections, 0))
			desired := base + (load+9)/10
			if c.config.AggressivePool {
				desired += (load + 9) / 10
			}
			if desired > maximum {
				desired = maximum
			}
			target = desired
		}
		fill()
	}
}

func (c *httpClientSession) channelHandler() {
	// Cancellation closes the socket; no reader goroutine or message queue is needed.
	timeout := c.config.HeartbeatTimeout
	if timeout <= 0 {
		timeout = 180 * time.Second
	}
	for c.ctx.Err() == nil {
		_ = c.controlChannel.SetReadDeadline(time.Now().Add(timeout))
		msg, err := utils.ReceiveBinaryByte(c.controlChannel)
		if err != nil {
			if c.ctx.Err() == nil {
				c.logger.Debugf("HTTP control channel lost: %v", err)
			}
			return
		}
		switch msg {
		case utils.SG_Chan:
			atomic.AddInt32(&c.loadConnections, 1)
		case utils.SG_HB:
			_ = c.controlChannel.SetWriteDeadline(time.Now().Add(10 * time.Second))
			err := utils.SendBinaryByte(c.controlChannel, utils.SG_HB)
			if err != nil {
				return
			}
		case utils.SG_Closed:
			return
		default:
			c.logger.Warnf("unexpected HTTP control message: %d", msg)
			return
		}
	}
}

func (c *httpClientSession) tunnelDialer() {
	// The maintainer reserves a slot before spawning, bounding pending dials.
	waiting := true
	defer func() {
		if waiting {
			atomic.AddInt32(&c.poolConnections, -1)
		}
	}()
	conn, err := network.HttpDialer(c.ctx, c.config.RemoteAddr, c.config.EdgeIP, "/tunnel", c.config.DialTimeOut, c.config.KeepAlive, c.config.Nodelay, c.config.Token, c.config.Mode, 3, 0, 0, c.config.ECH)
	if err != nil {
		if c.ctx.Err() == nil {
			c.logger.Debugf("HTTP tunnel dial failed: %v", err)
		}
		return
	}
	if !c.connections.Add(conn) {
		return
	}
	defer c.connections.Close(conn)
	remoteAddr, transport, err := utils.ReceiveBinaryTransportString(conn)
	if err != nil {
		return
	}
	atomic.AddInt32(&c.poolConnections, -1)
	waiting = false
	select {
	case c.poolWake <- struct{}{}:
	default:
	}
	port, resolvedAddr, err := network.ResolveRemoteAddr(remoteAddr)
	if err != nil {
		return
	}
	if transport == utils.SG_TCP {
		c.localDialer(conn, resolvedAddr, port)
	}
}

func (c *httpClientSession) localDialer(tunnelConn net.Conn, remoteAddr string, port int) {
	var sendBuf, recvBuf int

	if strings.Contains(remoteAddr, "127.0.0.1") {
		// Use 32 KB for localhost
		sendBuf = 32 * 1024
		recvBuf = 32 * 1024
	} else {
		// Use default buffer sizes
		sendBuf = 0
		recvBuf = 0
	}

	localConnection, err := network.TcpDialer(c.ctx, remoteAddr, "", c.config.DialTimeOut, c.config.KeepAlive, true, 1, recvBuf, sendBuf, 0)
	if err != nil {
		c.logger.Errorf("local dialer: %v", err)
		tunnelConn.Close()
		return
	}
	c.logger.Debugf("connected to local address %s successfully", remoteAddr)

	handlers.TCPConnectionHandler(c.ctx, false, tunnelConn, localConnection, c.logger, c.usageMonitor, port, c.config.Sniffer)
}
