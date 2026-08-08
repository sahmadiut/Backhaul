package transport

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sahmadiut/backhaul/config"
	"github.com/sahmadiut/backhaul/internal/utils"
	"github.com/sahmadiut/backhaul/internal/utils/handlers"
	"github.com/sahmadiut/backhaul/internal/web"

	"github.com/sirupsen/logrus"
)

type HttpTransport struct {
	config         *HttpConfig
	parentctx      context.Context
	ctx            context.Context
	cancel         context.CancelFunc
	logger         *logrus.Logger
	tunnelChannel  chan net.Conn
	localChannel   chan LocalTCPConn
	reqNewConnChan chan struct{}
	controlChannel net.Conn
	restartMutex   sync.Mutex
	usageMonitor   *web.Usage
	expectedAuth   string // pre-computed "Bearer <token>" to avoid fmt.Sprintf per request
}

type HttpConfig struct {
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

func NewHTTPServer(parentCtx context.Context, config *HttpConfig, logger *logrus.Logger) *HttpTransport {
	ctx, cancel := context.WithCancel(parentCtx)

	server := &HttpTransport{
		config:         config,
		parentctx:      parentCtx,
		ctx:            ctx,
		cancel:         cancel,
		logger:         logger,
		tunnelChannel:  make(chan net.Conn, config.ChannelSize),
		localChannel:   make(chan LocalTCPConn, config.ChannelSize),
		reqNewConnChan: make(chan struct{}, config.ChannelSize),
		controlChannel: nil,
		usageMonitor:   web.NewDataStore(fmt.Sprintf(":%v", config.WebPort), ctx, config.SnifferLog, config.Sniffer, &config.TunnelStatus, logger),
		expectedAuth:   "Bearer " + config.Token,
	}

	return server
}

func (s *HttpTransport) Start() {
	// for webui
	if s.config.WebPort > 0 {
		go s.usageMonitor.Monitor()
	}

	s.config.TunnelStatus = fmt.Sprintf("Disconnected (%s)", s.config.Mode)

	go s.tunnelListener()
}

func (s *HttpTransport) Restart() {
	if !s.restartMutex.TryLock() {
		s.logger.Warn("server restart already in progress, skipping restart attempt")
		return
	}
	defer s.restartMutex.Unlock()

	s.logger.Info("restarting server...")

	level := s.logger.Level
	s.logger.SetLevel(logrus.FatalLevel)

	oldTunnelChannel := s.tunnelChannel
	oldLocalChannel := s.localChannel

	if s.cancel != nil {
		s.cancel()
	}

	// Close control channel connection
	if s.controlChannel != nil {
		s.controlChannel.Close()
	}

	time.Sleep(2 * time.Second)
	drainHTTPConnections(oldTunnelChannel, oldLocalChannel)

	ctx, cancel := context.WithCancel(s.parentctx)
	s.ctx = ctx
	s.cancel = cancel

	// Re-initialize variables
	s.tunnelChannel = make(chan net.Conn, s.config.ChannelSize)
	s.localChannel = make(chan LocalTCPConn, s.config.ChannelSize)
	s.reqNewConnChan = make(chan struct{}, s.config.ChannelSize)
	s.controlChannel = nil
	s.usageMonitor = web.NewDataStore(fmt.Sprintf(":%v", s.config.WebPort), ctx, s.config.SnifferLog, s.config.Sniffer, &s.config.TunnelStatus, s.logger)
	s.config.TunnelStatus = ""

	// set the log level again
	s.logger.SetLevel(level)

	go s.Start()
}

func drainHTTPConnections(tunnelChannel <-chan net.Conn, localChannel <-chan LocalTCPConn) {
	for {
		select {
		case conn := <-tunnelChannel:
			conn.Close()
		default:
			goto drainLocal
		}
	}

drainLocal:
	for {
		select {
		case conn := <-localChannel:
			conn.conn.Close()
		default:
			return
		}
	}
}

func (s *HttpTransport) channelHandler() {
	ctx := s.ctx
	controlChannel := s.controlChannel
	reqNewConnChan := s.reqNewConnChan
	ticker := time.NewTicker(s.config.Heartbeat)
	defer ticker.Stop()

	// Channel to receive the message or error
	messageChan := make(chan byte, 10)

	// Separate goroutine to continuously listen for messages
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				message, err := utils.ReceiveBinaryByte(controlChannel)
				if err != nil {
					if s.cancel != nil {
						s.logger.Error("failed to read from channel connection. ", err)
						go s.Restart()
					}
					return
				}
				select {
				case messageChan <- message:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			_ = utils.SendBinaryByte(controlChannel, utils.SG_Closed)
			return
		case <-reqNewConnChan:
			err := utils.SendBinaryByte(controlChannel, utils.SG_Chan)
			if err != nil {
				s.logger.Error("failed to send request new connection signal. ", err)
				go s.Restart()
				return
			}

		case <-ticker.C:
			err := utils.SendBinaryByte(controlChannel, utils.SG_HB)
			if err != nil {
				s.logger.Errorf("failed to send heartbeat signal. Error: %v.", err)
				go s.Restart()
				return
			}
			s.logger.Debug("heartbeat signal sent successfully")

		case msg, ok := <-messageChan:
			if !ok {
				s.logger.Error("channel closed, likely due to an error in read")
				return
			}
			switch msg {
			case utils.SG_HB:
				s.logger.Trace("heartbeat signal received successfully")

			case utils.SG_Closed:
				s.logger.Warn("control channel has been closed by the client")
				s.Restart()
				return

			default:
				s.logger.Errorf("unexpected response from channel: %v", msg)
				go s.Restart()
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

func (s *HttpTransport) tunnelListener() {
	addr := s.config.BindAddr

	// Create an HTTP server that hijacks connections
	server := &http.Server{
		Addr:              addr,
		IdleTimeout:       httpIdleTimeout,
		ReadHeaderTimeout: 10 * time.Second, // prevent slowloris attacks and resource leaks
		MaxHeaderBytes:    maxHTTPHeaderBytes,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

			// Send 101 Switching Protocols response
			const response = "HTTP/1.1 101 Switching Protocols\r\n" +
				"Upgrade: backhaul\r\n" +
				"Connection: Upgrade\r\n" +
				"\r\n"
			if _, err := bufrw.WriteString(response); err != nil {
				s.logger.Errorf("failed to send 101 response to %s: %v", r.RemoteAddr, err)
				conn.Close()
				return
			}
			if err := bufrw.Flush(); err != nil {
				s.logger.Errorf("failed to flush response to %s: %v", r.RemoteAddr, err)
				conn.Close()
				return
			}

			if r.URL.Path == "/channel" {
				if s.controlChannel != nil {
					s.logger.Warn("new control channel requested.")
					s.controlChannel.Close()
					conn.Close()
					go s.Restart()
					return
				}
				s.controlChannel = conn

				s.logger.Info("control channel established successfully")

				numCPU := runtime.NumCPU()
				if numCPU > 4 {
					numCPU = 4 // Max allowed handler is 4
				}

				go s.channelHandler()
				go s.parsePortMappings()

				s.logger.Infof("starting %d handle loops on each CPU thread", numCPU)

				for i := 0; i < numCPU; i++ {
					go s.handleLoop()
				}

				s.config.TunnelStatus = fmt.Sprintf("Connected (%s)", s.config.Mode)

			} else if isTunnel {
				select {
				case s.tunnelChannel <- conn:
					s.logger.Debugf("http tunnel connection accepted from %s", conn.RemoteAddr().String())
				default:
					s.logger.Warnf("http tunnel channel is full, closing connection from %s", conn.RemoteAddr().String())
					conn.Close()
				}
			}
		}),
	}

	if s.config.Mode == config.HTTP {
		go func() {
			s.logger.Infof("http server starting, listening on %s", addr)
			if s.controlChannel == nil {
				s.logger.Info("waiting for http control channel connection")
			}
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				s.logger.Fatalf("failed to listen on %s: %v", addr, err)
			}
		}()
	} else {
		go func() {
			s.logger.Infof("https server starting, listening on %s", addr)
			if s.controlChannel == nil {
				s.logger.Info("waiting for https control channel connection")
			}
			if err := server.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				s.logger.Fatalf("failed to listen on %s: %v", addr, err)
			}
		}()
	}

	<-s.ctx.Done()

	// Gracefully shutdown the server without blocking restarts indefinitely.
	s.logger.Infof("shutting down the HTTP server on %s", addr)
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		s.logger.Errorf("failed to gracefully shutdown the server: %v", err)
		_ = server.Close()
	}

	if s.controlChannel != nil {
		s.controlChannel.Close()
	}
}

func (s *HttpTransport) parsePortMappings() {
	for _, portMapping := range s.config.Ports {
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
					localAddr = fmt.Sprintf(":%d", port)
					go s.localListener(localAddr, strconv.Itoa(port))
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
					localAddr = fmt.Sprintf(":%d", port)
					go s.localListener(localAddr, remoteAddr)
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
		go s.localListener(localAddr, remoteAddr)
	}
}

func (s *HttpTransport) localListener(localAddr string, remoteAddr string) {
	portListener, err := net.Listen("tcp", localAddr)
	if err != nil {
		s.logger.Fatalf("failed to start listener on %s: %v", localAddr, err)
		return
	}

	//close local listener after context cancellation
	defer portListener.Close()

	s.logger.Infof("listener started successfully, listening on address: %s", portListener.Addr().String())

	go s.acceptLocalConn(portListener, remoteAddr)

	<-s.ctx.Done()
}

func (s *HttpTransport) acceptLocalConn(listener net.Listener, remoteAddr string) {
	for {
		select {
		case <-s.ctx.Done():
			return

		default:
			s.logger.Debugf("waiting to accept incoming connection on %s", listener.Addr().String())
			conn, err := listener.Accept()
			if err != nil {
				s.logger.Debugf("failed to accept connection on %s: %v", listener.Addr().String(), err)
				continue
			}

			// discard any non-tcp connection
			tcpConn, ok := conn.(*net.TCPConn)
			if !ok {
				s.logger.Warnf("disarded non-TCP connection from %s", conn.RemoteAddr().String())
				conn.Close()
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
				conn.Close()
			}
		}
	}
}

func (s *HttpTransport) handleLoop() {
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
				localConn.conn.Close()
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

			timer := time.NewTimer(remaining)
		loop:
			for {
				select {
				case <-s.ctx.Done():
					timer.Stop()
					localConn.conn.Close()
					return

				case <-timer.C:
					s.logger.Debugf("timeouted local connection: %d ms", time.Now().UnixMilli()-localConn.timeCreated)
					localConn.conn.Close()
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

func (s *HttpTransport) pairHTTPConnections(localConn LocalTCPConn, tunnelConn net.Conn) bool {
	if err := utils.SendBinaryTransportString(tunnelConn, localConn.remoteAddr, utils.SG_TCP); err != nil {
		s.logger.Errorf("%v", err)
		tunnelConn.Close()
		return false
	}

	port := localConn.conn.LocalAddr().(*net.TCPAddr).Port
	go handlers.TCPConnectionHandler(s.ctx, false, localConn.conn, tunnelConn, s.logger, s.usageMonitor, port, s.config.Sniffer)
	return true
}
