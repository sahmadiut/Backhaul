package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sahmadiut/backhaul/config"
	"github.com/sahmadiut/backhaul/internal/ech"
	"github.com/sahmadiut/backhaul/internal/utils"
	"github.com/sahmadiut/backhaul/internal/utils/handlers"
	"github.com/sahmadiut/backhaul/internal/utils/network"
	"github.com/sahmadiut/backhaul/internal/web"

	"github.com/sirupsen/logrus"
)

type HttpTransport struct {
	config       *HttpConfig
	parentctx    context.Context
	logger       *logrus.Logger
	usageMonitor *web.Usage
	expectedAuth string
	startOnce    sync.Once
	restartMutex sync.Mutex
	cancel       context.CancelFunc
}

type httpServerSession struct {
	*HttpTransport
	ctx            context.Context
	cancel         context.CancelFunc
	tunnelChannel  chan net.Conn
	localChannel   chan LocalTCPConn
	reqNewConnChan chan struct{}
	controlChannel net.Conn
	controlMutex   sync.Mutex
	connections    network.ConnectionSet
	workers        sync.WaitGroup
}

func (s *httpServerSession) launch(fn func()) {
	s.workers.Add(1)
	go func() { defer s.workers.Done(); fn() }()
}

type HttpConfig struct {
	ECH          *ech.Server
	BindAddr     string
	SnifferLog   string
	TLSCertFile  string
	TLSKeyFile   string
	TunnelStatus string
	Token        string
	Ports        []string
	Nodelay      bool
	Sniffer      bool
	KeepAlive    time.Duration
	Heartbeat    time.Duration
	ChannelSize  int
	WebPort      int
	Mode         config.TransportType // http or https
}

const (
	maxHTTPHeaderBytes = 8 << 10
	httpIdleTimeout    = 30 * time.Second
)

const nginxWelcomePage = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
`

var nginxWelcomePageBytes = []byte(nginxWelcomePage)

func NewHTTPServer(parentCtx context.Context, cfg *HttpConfig, logger *logrus.Logger) *HttpTransport {
	return &HttpTransport{
		config: cfg, parentctx: parentCtx, logger: logger, expectedAuth: "Bearer " + cfg.Token,
		usageMonitor: web.NewDataStore(fmt.Sprintf(":%v", cfg.WebPort), parentCtx, cfg.SnifferLog, cfg.Sniffer, &cfg.TunnelStatus, logger),
	}
}

func (s *HttpTransport) Start() {
	s.startOnce.Do(func() {
		if s.config.WebPort > 0 {
			go s.usageMonitor.Monitor()
		}
		go s.run()
	})
}

func (s *HttpTransport) Restart() {
	s.restartMutex.Lock()
	defer s.restartMutex.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *HttpTransport) run() {
	for s.parentctx.Err() == nil {
		ctx, cancel := context.WithCancel(s.parentctx)
		session := &httpServerSession{
			HttpTransport: s, ctx: ctx, cancel: cancel,
			tunnelChannel:  make(chan net.Conn, s.config.ChannelSize),
			localChannel:   make(chan LocalTCPConn, s.config.ChannelSize),
			reqNewConnChan: make(chan struct{}, s.config.ChannelSize),
		}
		s.restartMutex.Lock()
		s.cancel = cancel
		s.restartMutex.Unlock()
		s.usageMonitor.SetTunnelStatus(fmt.Sprintf("Disconnected (%s)", s.config.Mode))
		stop := context.AfterFunc(ctx, session.connections.CloseAll)
		// The listener remains a producer until Shutdown has stopped HTTP handlers.
		session.launch(session.tunnelListener)
		session.workers.Wait()
		cancel()
		session.connections.CloseAll()
		stop()
		s.usageMonitor.SetTunnelStatus(fmt.Sprintf("Disconnected (%s)", s.config.Mode))
		timer := time.NewTimer(time.Second)
		select {
		case <-s.parentctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (s *httpServerSession) channelHandler(conn net.Conn) {
	defer s.cancel()
	heartbeat := s.config.Heartbeat
	if heartbeat <= 0 {
		heartbeat = 40 * time.Second
	}
	ticker := time.NewTicker(heartbeat)
	defer ticker.Stop()
	messages := make(chan byte, 1)
	s.launch(func() {
		defer close(messages)
		for {
			// Three missed heartbeat intervals mark an unresponsive client as dead.
			_ = conn.SetReadDeadline(time.Now().Add(3 * heartbeat))
			message, err := utils.ReceiveBinaryByte(conn)
			if err != nil {
				return
			}
			select {
			case messages <- message:
			case <-s.ctx.Done():
				return
			}
		}
	})
	send := func(message byte) bool {
		_ = conn.SetWriteDeadline(time.Now().Add(heartbeat))
		return utils.SendBinaryByte(conn, message) == nil
	}
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.reqNewConnChan:
			if !send(utils.SG_Chan) {
				return
			}
		case <-ticker.C:
			if !send(utils.SG_HB) {
				return
			}
		case message, ok := <-messages:
			if !ok || message != utils.SG_HB {
				return
			}
		}
	}
}

func (s *HttpTransport) isBackhaulUpgradeRequest(r *http.Request) bool {
	if r.Method != http.MethodGet || r.Header.Get("Authorization") != s.expectedAuth {
		return false
	}

	if !strings.EqualFold(r.Header.Get("Upgrade"), "backhaul") {
		return false
	}

	return r.URL.Path == "/channel" || r.URL.Path == "/tunnel" || strings.HasPrefix(r.URL.Path, "/tunnel/")
}

func serveNginxWelcomePage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Server", "nginx")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(nginxWelcomePageBytes)
}

func (s *httpServerSession) tunnelListener() {
	addr := s.config.BindAddr

	// Create an HTTP server that hijacks connections
	server := &http.Server{
		Addr:              addr,
		IdleTimeout:       httpIdleTimeout,
		ReadHeaderTimeout: 10 * time.Second, // prevent slowloris attacks and resource leaks
		MaxHeaderBytes:    maxHTTPHeaderBytes,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.workers.Add(1)
			defer s.workers.Done()
			s.logger.Tracef("received http request from %s", r.RemoteAddr)

			if !s.isBackhaulUpgradeRequest(r) {
				if s.config.Mode == config.HTTPS {
					serveNginxWelcomePage(w)
					return
				}
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			isTunnel := r.URL.Path == "/tunnel" || strings.HasPrefix(r.URL.Path, "/tunnel/")

			// Hijack the connection
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				s.logger.Error("server doesn't support hijacking")
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			conn, bufrw, err := hijacker.Hijack()
			if err != nil {
				s.logger.Errorf("failed to hijack connection from %s: %v", r.RemoteAddr, err)
				return
			}

			if !s.connections.Add(conn) {
				return
			}
			// Bound writes to peers that stop reading during the upgrade.
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			// Send 101 Switching Protocols response
			const response = "HTTP/1.1 101 Switching Protocols\r\n" +
				"Upgrade: backhaul\r\n" +
				"Connection: Upgrade\r\n" +
				"\r\n"
			if _, err := bufrw.WriteString(response); err != nil {
				s.logger.Errorf("failed to send 101 response to %s: %v", r.RemoteAddr, err)
				s.connections.Close(conn)
				return
			}
			if err := bufrw.Flush(); err != nil {
				s.logger.Errorf("failed to flush response to %s: %v", r.RemoteAddr, err)
				s.connections.Close(conn)
				return
			}

			_ = conn.SetDeadline(time.Time{})
			if r.URL.Path == "/channel" {
				s.controlMutex.Lock()
				if s.controlChannel != nil {
					s.logger.Warn("new control channel requested.")
					s.controlMutex.Unlock()
					s.connections.Close(conn)
					s.cancel()
					return
				}
				s.controlChannel = conn
				s.controlMutex.Unlock()

				s.logger.Info("control channel established successfully")

				numCPU := runtime.NumCPU()
				if numCPU > 4 {
					numCPU = 4 // Max allowed handler is 4
				}

				s.launch(func() { s.channelHandler(conn) })
				s.launch(s.parsePortMappings)

				s.logger.Infof("starting %d handle loops on each CPU thread", numCPU)

				for i := 0; i < numCPU; i++ {
					s.launch(s.handleLoop)
				}

				s.usageMonitor.SetTunnelStatus(fmt.Sprintf("Connected (%s)", s.config.Mode))

			} else if isTunnel {
				select {
				case s.tunnelChannel <- conn:
					s.logger.Debugf("http tunnel connection accepted from %s", conn.RemoteAddr().String())
				default:
					s.logger.Warnf("http tunnel channel is full, closing connection from %s", conn.RemoteAddr().String())
					s.connections.Close(conn)
				}
			}
		}),
	}

	echTLS, err := s.config.ECH.TLSConfig()
	if err != nil {
		s.logger.Errorf("ECH setup: %v", err)
		s.cancel()
		return
	}
	server.TLSConfig = echTLS
	// Disable HTTP/2: the Backhaul protocol needs HTTP/1.1 hijacking.
	server.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		var err error
		if s.config.Mode == config.HTTP {
			err = server.ListenAndServe()
		} else {
			err = server.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile)
		}
		if err != nil && err != http.ErrServerClosed {
			s.logger.Errorf("HTTP listener failed on %s: %v", addr, err)
			s.cancel()
		}
	}()
	<-s.ctx.Done()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
	}
	<-serveDone
}

func (s *httpServerSession) parsePortMappings() {
	for _, portMapping := range s.config.Ports {
		if s.ctx.Err() != nil {
			return
		}
		parts := strings.Split(portMapping, "=")

		var localAddr, remoteAddr string

		// Check if only a single port or a port range is provided (no "=" present)
		if len(parts) == 1 {
			localPortOrRange := strings.TrimSpace(parts[0])
			remoteAddr = localPortOrRange // If no remote addr is provided, use the local port as the remote port

			// Check if it's a port range
			if strings.Contains(localPortOrRange, "-") {
				rangeParts := strings.Split(localPortOrRange, "-")
				if len(rangeParts) != 2 {
					s.logger.Fatalf("invalid port range format: %s", localPortOrRange)
				}

				// Parse and validate start and end ports
				startPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				if err != nil || startPort < 1 || startPort > 65535 {
					s.logger.Fatalf("invalid start port in range: %s", rangeParts[0])
				}

				endPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				if err != nil || endPort < 1 || endPort > 65535 || endPort < startPort {
					s.logger.Fatalf("invalid end port in range: %s", rangeParts[1])
				}

				// Create listeners for all ports in the range
				for port := startPort; port <= endPort; port++ {
					if s.ctx.Err() != nil {
						return
					}
					localAddr = fmt.Sprintf(":%d", port)
					addr, remote := localAddr, strconv.Itoa(port)
					s.launch(func() { s.localListener(addr, remote) })
					time.Sleep(1 * time.Millisecond) // for wide port ranges
				}
				continue
			} else {
				// Handle single port case
				port, err := strconv.Atoi(localPortOrRange)
				if err != nil || port < 1 || port > 65535 {
					s.logger.Fatalf("invalid port format: %s", localPortOrRange)
				}
				localAddr = fmt.Sprintf(":%d", port)
			}
		} else if len(parts) == 2 {
			// Handle "local=remote" format
			localPortOrRange := strings.TrimSpace(parts[0])
			remoteAddr = strings.TrimSpace(parts[1])

			// Check if local port is a range
			if strings.Contains(localPortOrRange, "-") {
				rangeParts := strings.Split(localPortOrRange, "-")
				if len(rangeParts) != 2 {
					s.logger.Fatalf("invalid port range format: %s", localPortOrRange)
				}

				// Parse and validate start and end ports
				startPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				if err != nil || startPort < 1 || startPort > 65535 {
					s.logger.Fatalf("invalid start port in range: %s", rangeParts[0])
				}

				endPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				if err != nil || endPort < 1 || endPort > 65535 || endPort < startPort {
					s.logger.Fatalf("invalid end port in range: %s", rangeParts[1])
				}

				// Create listeners for all ports in the range
				for port := startPort; port <= endPort; port++ {
					if s.ctx.Err() != nil {
						return
					}
					localAddr = fmt.Sprintf(":%d", port)
					addr, remote := localAddr, remoteAddr
					s.launch(func() { s.localListener(addr, remote) })
					time.Sleep(1 * time.Millisecond) // for wide port ranges
				}
				continue
			} else {
				// Handle single local port case
				port, err := strconv.Atoi(localPortOrRange)
				if err == nil && port > 1 && port < 65535 { // format port=remoteAddress
					localAddr = fmt.Sprintf(":%d", port)
				} else {
					localAddr = localPortOrRange // format ip:port=remoteAddress
				}
			}
		} else {
			s.logger.Fatalf("invalid port mapping format: %s", portMapping)
		}
		// Start listeners for single port
		addr, remote := localAddr, remoteAddr
		s.launch(func() { s.localListener(addr, remote) })
	}
}

func (s *httpServerSession) localListener(localAddr string, remoteAddr string) {
	portListener, err := net.Listen("tcp", localAddr)
	if err != nil {
		s.logger.Errorf("failed to start listener on %s: %v", localAddr, err)
		s.cancel()
		return
	}

	//close local listener after context cancellation
	defer portListener.Close()

	s.logger.Infof("listener started successfully, listening on address: %s", portListener.Addr().String())

	stop := context.AfterFunc(s.ctx, func() { portListener.Close() })
	defer stop()
	s.acceptLocalConn(portListener, remoteAddr)
}

func (s *httpServerSession) acceptLocalConn(listener net.Listener, remoteAddr string) {
	for {
		select {
		case <-s.ctx.Done():
			return

		default:
			s.logger.Debugf("waiting to accept incoming connection on %s", listener.Addr().String())
			conn, err := listener.Accept()
			if err != nil {
				if s.ctx.Err() == nil {
					s.logger.Debugf("local accept failed: %v", err)
					s.cancel()
				}
				return
			}

			if !s.connections.Add(conn) {
				return
			}
			// discard any non-tcp connection
			tcpConn, ok := conn.(*net.TCPConn)
			if !ok {
				s.logger.Warnf("disarded non-TCP connection from %s", conn.RemoteAddr().String())
				s.connections.Close(conn)
				continue
			}

			// trying to enable tcpnodelay
			if !s.config.Nodelay {
				if err := tcpConn.SetNoDelay(s.config.Nodelay); err != nil {
					s.logger.Warnf("failed to set TCP_NODELAY for %s: %v", tcpConn.RemoteAddr().String(), err)
				} else {
					s.logger.Tracef("TCP_NODELAY disabled for %s", tcpConn.RemoteAddr().String())
				}
			}

			// Set keep-alive settings
			if err := tcpConn.SetKeepAlive(true); err != nil {
				s.logger.Warnf("failed to enable TCP keep-alive for %s: %v", tcpConn.RemoteAddr().String(), err)
			} else {
				s.logger.Tracef("TCP keep-alive enabled for %s", tcpConn.RemoteAddr().String())
			}
			if err := tcpConn.SetKeepAlivePeriod(s.config.KeepAlive); err != nil {
				s.logger.Warnf("failed to set TCP keep-alive period for %s: %v", tcpConn.RemoteAddr().String(), err)
			}

			select {
			case s.localChannel <- LocalTCPConn{conn: conn, remoteAddr: remoteAddr, timeCreated: time.Now().UnixMilli()}:

				select {
				case s.reqNewConnChan <- struct{}{}:
					// Successfully requested a new connection
				default:
					// The channel is full, do nothing
					s.logger.Warn("channel is full, cannot request a new connection")
				}

				s.logger.Debugf("accepted incoming TCP connection from %s", tcpConn.RemoteAddr().String())

			default: // channel is full, discard the connection
				s.logger.Warnf("channel with listener %s is full, discarding TCP connection from %s", listener.Addr().String(), tcpConn.LocalAddr().String())
				s.connections.Close(conn)
			}
		}
	}
}

func (s *httpServerSession) handleLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case localConn := <-s.localChannel:
			now := time.Now().UnixMilli()
			elapsed := time.Duration(now-localConn.timeCreated) * time.Millisecond
			remaining := 3*time.Second - elapsed
			if remaining <= 0 {
				s.logger.Debugf("timeouted local connection: %d ms", now-localConn.timeCreated)
				s.connections.Close(localConn.conn)
				continue
			}

			// The pool is normally warm. Avoid allocating a timer on this hot path.
			select {
			case tunnelConn := <-s.tunnelChannel:
				if s.pairHTTPConnections(localConn, tunnelConn) {
					continue
				}
			default:
			}

			// A failed assignment write may have consumed the pairing budget.
			remaining = time.Until(time.UnixMilli(localConn.timeCreated).Add(3 * time.Second))
			if remaining <= 0 {
				s.connections.Close(localConn.conn)
				continue
			}
			timer := time.NewTimer(remaining)
		loop:
			for {
				select {
				case <-s.ctx.Done():
					timer.Stop()
					s.connections.Close(localConn.conn)
					return

				case <-timer.C:
					s.logger.Debugf("timeouted local connection: %d ms", time.Now().UnixMilli()-localConn.timeCreated)
					s.connections.Close(localConn.conn)
					break loop

				case tunnelConn := <-s.tunnelChannel:
					if s.pairHTTPConnections(localConn, tunnelConn) {
						timer.Stop()
						break loop
					}
				}
			}
		}
	}
}

func (s *httpServerSession) pairHTTPConnections(localConn LocalTCPConn, tunnelConn net.Conn) bool {
	deadline := time.UnixMilli(localConn.timeCreated).Add(3 * time.Second)
	if s.ctx.Err() != nil || !time.Now().Before(deadline) {
		s.connections.Close(tunnelConn)
		return false
	}
	_ = tunnelConn.SetWriteDeadline(deadline)
	if err := utils.SendBinaryTransportString(tunnelConn, localConn.remoteAddr, utils.SG_TCP); err != nil {
		s.logger.Errorf("%v", err)
		s.connections.Close(tunnelConn)
		return false
	}

	_ = tunnelConn.SetWriteDeadline(time.Time{})
	port := localConn.conn.LocalAddr().(*net.TCPAddr).Port
	s.launch(func() {
		defer s.connections.Close(localConn.conn)
		defer s.connections.Close(tunnelConn)
		handlers.TCPConnectionHandler(s.ctx, false, localConn.conn, tunnelConn, s.logger, s.usageMonitor, port, s.config.Sniffer)
	})
	return true
}
