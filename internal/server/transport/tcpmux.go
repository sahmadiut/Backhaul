package transport

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sahmadiut/backhaul/internal/utils"

	"github.com/sirupsen/logrus"
	"github.com/xtaci/smux"
)

type TcpMuxTransport struct {
	config       *TcpMuxConfig
	ctx          context.Context
	cancel       context.CancelFunc
	logger       *logrus.Logger
	smuxSession  []*smux.Session
	restartMutex sync.Mutex
	timeout      time.Duration
	usageMonitor *utils.Usage
}

type TcpMuxConfig struct {
	BindAddr         string
	Nodelay          bool
	KeepAlive        time.Duration
	Token            string
	MuxSession       int
	ChannelSize      int
	Ports            []string
	MuxVersion       int
	MaxFrameSize     int
	MaxReceiveBuffer int
	MaxStreamBuffer  int
	Sniffing         bool
	WebPort          int
	SnifferLog       string
}

func NewTcpMuxServer(parentCtx context.Context, config *TcpMuxConfig, logger *logrus.Logger) *TcpMuxTransport {
	// Create a derived context from the parent context
	ctx, cancel := context.WithCancel(parentCtx)

	// Initialize the TcpTransport struct
	server := &TcpMuxTransport{
		config:       config,
		ctx:          ctx,
		cancel:       cancel,
		logger:       logger,
		timeout:      2 * time.Second, // Default timeout
		smuxSession:  make([]*smux.Session, config.MuxSession),
		usageMonitor: utils.NewDataStore(fmt.Sprintf(":%v", config.WebPort), ctx, config.SnifferLog, logger),
	}

	return server
}

func (s *TcpMuxTransport) Restart() {
	if !s.restartMutex.TryLock() {
		s.logger.Warn("server restart already in progress, skipping restart attempt")
		return
	}
	defer s.restartMutex.Unlock()

	s.logger.Info("restarting server...")
	if s.cancel != nil {
		s.cancel()
	}

	time.Sleep(2 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	s.ctx = ctx
	s.cancel = cancel

	// Re-initialize variables
	s.smuxSession = make([]*smux.Session, s.config.MuxSession)
	s.usageMonitor = utils.NewDataStore(fmt.Sprintf(":%v", s.config.WebPort), ctx, s.config.SnifferLog, s.logger)

	go s.TunnelListener()

}

func (s *TcpMuxTransport) portConfigReader() {
	// port mapping for listening on each local port
	for _, portMapping := range s.config.Ports {
		var re = regexp.MustCompile(`(?m)^(?:(?:\[(\d+):(\d+)\](?:=(\d+))?)|(?:(\d+)(?::(\d+))?(?:=(\d+))?))$`)
		if !re.MatchString(portMapping) {
			s.logger.Fatalf("invalid port mapping: %s", portMapping)
			continue
		}
		var groups = re.FindStringSubmatch(portMapping)
		var validGroups []int
		for i := 1; i < len(groups); i++ {
			if groups[i] != "" {
				var num, _ = strconv.Atoi(groups[i])
				validGroups = append(validGroups, num)
			}
		}
		var remotePort = -1
		var startRange = validGroups[0]
		var endRange = startRange
		if strings.Contains(portMapping, "=") {
			remotePort = validGroups[len(validGroups)-1]
			if len(validGroups) == 3 {
				endRange = validGroups[1]
			}
		} else {
			if len(validGroups) == 2 {
				endRange = validGroups[1]
			}
		}
		if startRange > endRange {
			s.logger.Fatalf("Invalid range: %d %d", startRange, endRange)
		} else {
			for i := startRange; i <= endRange; i++ {
				var localAddr = ":" + strconv.Itoa(i)
				if remotePort == -1 {
					go s.localListener(localAddr, i)
				} else {
					go s.localListener(localAddr, remotePort)
				}
			}
		}
	}
}

func (s *TcpMuxTransport) TunnelListener() {
	tunnelListener, err := net.Listen("tcp", s.config.BindAddr)
	if err != nil {
		s.logger.Fatalf("failed to start listener on %s: %v", s.config.BindAddr, err)
		return
	}

	// close the tun listener after context cancellation
	defer tunnelListener.Close()

	s.logger.Infof("server started successfully, listening on address: %s", tunnelListener.Addr().String())

	var wg sync.WaitGroup
	for id := 0; id < s.config.MuxSession; id++ {
		wg.Add(1)
		go s.acceptStreamConn(tunnelListener, id, &wg)
	}
	wg.Wait()

	go s.portConfigReader()

	if s.config.Sniffing {
		go s.usageMonitor.Monitor()
	}

	<-s.ctx.Done()
}

func (s *TcpMuxTransport) acceptStreamConn(listener net.Listener, id int, wg *sync.WaitGroup) {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			s.logger.Debugf("waiting for accept incoming tunnel connection on %s", listener.Addr().String())
			conn, err := listener.Accept()
			if err != nil {
				s.logger.Debugf("failed to accept tunnel connection on %s: %v", listener.Addr().String(), err)
				continue
			}

			//discard any non tcp connection
			tcpConn, ok := conn.(*net.TCPConn)
			if !ok {
				s.logger.Warnf("disarded non-TCP tunnel connection from %s", conn.RemoteAddr().String())
				conn.Close()
				continue
			}

			// trying to enable tcpnodelay
			if s.config.Nodelay {
				if err := tcpConn.SetNoDelay(s.config.Nodelay); err != nil {
					s.logger.Warnf("failed to set TCP_NODELAY for %s: %v", tcpConn.RemoteAddr().String(), err)
				} else {
					s.logger.Tracef("TCP_NODELAY enabled for %s", tcpConn.RemoteAddr().String())
				}
			}

			// config fot smux
			config := smux.Config{
				Version:           s.config.MuxVersion, // Smux protocol version
				KeepAliveInterval: 10 * time.Second,    // Shorter keep-alive interval to quickly detect dead peers
				KeepAliveTimeout:  30 * time.Second,    // Aggressive timeout to handle unresponsive connections
				MaxFrameSize:      s.config.MaxFrameSize,
				MaxReceiveBuffer:  s.config.MaxReceiveBuffer,
				MaxStreamBuffer:   s.config.MaxStreamBuffer,
			}
			// smux server
			session, err := smux.Client(conn, &config)
			if err != nil {
				s.logger.Errorf("failed to create SMUX session for connection %s: %v", conn.RemoteAddr().String(), err)
				conn.Close()
				continue
			}

			// auth
			stream, err := session.AcceptStream()
			if err != nil {
				s.logger.Errorf("failed to accept mux stream for authentication from session %v: %v", session, err)
				session.Close()
				continue

			}
			token, err := utils.ReceiveBinaryString(stream)
			if err != nil {
				s.logger.Errorf("failed to receive token from stream %v: %v", stream, err)
				session.Close()
				continue
			}
			if token == s.config.Token {
				err = utils.SendBinaryString(stream, "ok")
				if err != nil {
					s.logger.Errorf("failed to send acknowledgment for token to stream %v: %v", stream, err)
					session.Close()
					continue
				}
				s.smuxSession[id] = session
				s.logger.Infof("successfully established SMUX session with ID %d for connection %s", id, conn.RemoteAddr().String())

				// Graceful shutdown
				defer func() {
					if err := session.Close(); err != nil {
						s.logger.Warnf("failed to close SMUX session with ID %d: %v", id, err)
					} else {
						s.logger.Infof("SMUX session with ID %d closed successfully", id)
					}
				}()

				wg.Done()
				<-s.ctx.Done()
				return

			} else {
				err = utils.SendBinaryString(stream, "error")
				if err != nil {
					s.logger.Errorf("failed to send error response to stream %v: %v", stream, err)
				}

				s.logger.Errorf("failed to establish a new session. Token mismatch: received %s, expected %s", token, s.config.Token)
				session.Close()

				// For safety
				time.Sleep(2 * time.Second)
			}
		}
	}
}

func (s *TcpMuxTransport) localListener(localAddr string, remotePort int) {
	s.logger.Debugf("starting listener on local port %s -> remote port %d", localAddr, remotePort)
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		s.logger.Fatalf("failed to start listener on %s: %v", localAddr, err)
		return
	}

	//close local listener after context cancellation
	defer listener.Close()

	s.logger.Infof("listener started successfully, listening on address: %s", listener.Addr().String())

	// channel
	acceptChan := make(chan net.Conn, s.config.ChannelSize)

	// handle channel connections
	go s.handleMUXSession(acceptChan, remotePort)

	go func() {
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
				if s.config.Nodelay {
					if err := tcpConn.SetNoDelay(s.config.Nodelay); err != nil {
						s.logger.Warnf("failed to set TCP_NODELAY for %s: %v", tcpConn.RemoteAddr().String(), err)
					} else {
						s.logger.Tracef("TCP_NODELAY enabled for %s", tcpConn.RemoteAddr().String())
					}
				}

				tcpConn.SetKeepAlive(true)
				tcpConn.SetKeepAlivePeriod(s.config.KeepAlive)

				select {
				case acceptChan <- tcpConn:
					s.logger.Debugf("accepted incoming TCP connection from %s", tcpConn.RemoteAddr().String())

				case <-time.After(s.timeout): // channel is full, discard the connection
					s.logger.Warnf("channel with listener %s is full, discarding TCP connection from %s", listener.Addr().String(), tcpConn.LocalAddr().String())
					tcpConn.Close()
				}

			}
		}
	}()

	<-s.ctx.Done()
}

func (s *TcpMuxTransport) handleMUXSession(acceptChan chan net.Conn, remotePort int) {
	for {
		select {
		case incomingConn := <-acceptChan:
			id := rand.Intn(s.config.MuxSession)
			if s.smuxSession[id] == nil || s.smuxSession[id].IsClosed() {
				s.logger.Errorf("MUX session with ID %d is closed or nil. Discarding incoming connection from %s.", id, incomingConn.RemoteAddr().String())
				incomingConn.Close()
				s.logger.Info("attempting to restart server...")
				go s.Restart()
				return
			}

			stream, err := s.smuxSession[id].OpenStream()
			if err != nil {
				s.logger.Errorf("failed to open a new mux stream for session ID %d: %v", id, err)
				incomingConn.Close()
				s.logger.Info("attempting to restart server...")
				go s.Restart()
				return
			}
			// Send the target port over the connection
			if err := utils.SendBinaryInt(stream, uint16(remotePort)); err != nil {
				s.logger.Warnf("Failed to send port %d over stream for session ID %d: %v", remotePort, id, err)
				incomingConn.Close()
				continue
			}

			go utils.ConnectionHandler(stream, incomingConn, s.logger, s.usageMonitor, incomingConn.LocalAddr().(*net.TCPAddr).Port, s.config.Sniffing)

		case <-s.ctx.Done():
			return
		}
	}
}
