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
	"github.com/sahmadiut/backhaul/internal/utils"
	"github.com/sahmadiut/backhaul/internal/utils/handlers"
	"github.com/sahmadiut/backhaul/internal/utils/network"
	"github.com/sahmadiut/backhaul/internal/web"

	"github.com/sirupsen/logrus"
)

type HttpTransport struct {
	config          *HttpConfig
	parentctx       context.Context
	ctx             context.Context
	cancel          context.CancelFunc
	logger          *logrus.Logger
	controlChannel  net.Conn
	restartMutex    sync.Mutex
	usageMonitor    *web.Usage
	poolConnections int32
	loadConnections int32
	controlFlow     chan struct{}
}

type HttpConfig struct {
	RemoteAddr     string
	Token          string
	SnifferLog     string
	TunnelStatus   string
	Nodelay        bool
	Sniffer        bool
	KeepAlive      time.Duration
	RetryInterval  time.Duration
	DialTimeOut    time.Duration
	ConnPoolSize   int
	WebPort        int
	Mode           config.TransportType
	AggressivePool bool
	EdgeIP         string
}

func NewHTTPClient(parentCtx context.Context, config *HttpConfig, logger *logrus.Logger) *HttpTransport {
	ctx, cancel := context.WithCancel(parentCtx)

	client := &HttpTransport{
		config:          config,
		parentctx:       parentCtx,
		ctx:             ctx,
		cancel:          cancel,
		logger:          logger,
		controlChannel:  nil,
		usageMonitor:    web.NewDataStore(fmt.Sprintf(":%v", config.WebPort), ctx, config.SnifferLog, config.Sniffer, &config.TunnelStatus, logger),
		poolConnections: 0,
		loadConnections: 0,
		controlFlow:     make(chan struct{}, 100),
	}

	return client
}

func (c *HttpTransport) Start() {
	// for webui
	if c.config.WebPort > 0 {
		go c.usageMonitor.Monitor()
	}

	c.config.TunnelStatus = fmt.Sprintf("Disconnected (%s)", c.config.Mode)

	go c.channelDialer()
}

func (c *HttpTransport) Restart() {
	if !c.restartMutex.TryLock() {
		c.logger.Warn("client is already restarting")
		return
	}
	defer c.restartMutex.Unlock()

	c.logger.Info("restarting client...")

	// for removing timeout logs
	level := c.logger.Level
	c.logger.SetLevel(logrus.FatalLevel)

	if c.cancel != nil {
		c.cancel()
	}

	// close control channel connection
	if c.controlChannel != nil {
		c.controlChannel.Close()
	}

	time.Sleep(2 * time.Second)

	ctx, cancel := context.WithCancel(c.parentctx)
	c.ctx = ctx
	c.cancel = cancel

	// Re-initialize variables
	c.controlChannel = nil
	c.usageMonitor = web.NewDataStore(fmt.Sprintf(":%v", c.config.WebPort), ctx, c.config.SnifferLog, c.config.Sniffer, &c.config.TunnelStatus, c.logger)
	c.config.TunnelStatus = ""
	c.poolConnections = 0
	c.loadConnections = 0
	c.controlFlow = make(chan struct{}, 100)

	// set the log level again
	c.logger.SetLevel(level)

	go c.Start()
}

func (c *HttpTransport) channelDialer() {
	c.logger.Info("attempting to establish a new http control channel connection")

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			tunnelConn, err := network.HttpDialer(c.ctx, c.config.RemoteAddr, c.config.EdgeIP, "/channel", c.config.DialTimeOut, c.config.KeepAlive, true, c.config.Token, c.config.Mode, 3, 0, 0)
			if err != nil {
				c.logger.Errorf("control channel dialer: %v", err)
				time.Sleep(c.config.RetryInterval)
				continue
			}
			c.controlChannel = tunnelConn
			c.logger.Info("control channel established successfully")

			c.config.TunnelStatus = fmt.Sprintf("Connected (%s)", c.config.Mode)

			go c.poolMaintainer()
			go c.channelHandler()

			return
		}
	}
}

func (c *HttpTransport) poolMaintainer() {
	for i := 0; i < c.config.ConnPoolSize; i++ { //initial pool filling
		go c.tunnelDialer()
	}

	// factors
	a := 4
	b := 5
	x := 3
	y := 4.0

	if c.config.AggressivePool {
		c.logger.Info("aggressive pool management enabled")
		a = 1
		b = 2
		x = 0
		y = 0.75
	}

	tickerPool := time.NewTicker(time.Second * 1)
	defer tickerPool.Stop()

	tickerLoad := time.NewTicker(time.Second * 10)
	defer tickerLoad.Stop()

	newPoolSize := c.config.ConnPoolSize // intial value
	var poolConnectionsSum int32 = 0

	for {
		select {
		case <-c.ctx.Done():
			return

		case <-tickerPool.C:
			// Accumulate pool connections over time (every second)
			atomic.AddInt32(&poolConnectionsSum, atomic.LoadInt32(&c.poolConnections))

		case <-tickerLoad.C:
			// Calculate the loadConnections over the last 10 seconds
			loadConnections := (int(atomic.LoadInt32(&c.loadConnections)) + 9) / 10 // +9 for ceil-like logic
			atomic.StoreInt32(&c.loadConnections, 0)                                // Reset

			// Calculate the average pool connections over the last 10 seconds
			poolConnectionsAvg := (int(atomic.LoadInt32(&poolConnectionsSum)) + 9) / 10 // +9 for ceil-like logic
			atomic.StoreInt32(&poolConnectionsSum, 0)                                   // Reset

			// Dynamically adjust the pool size based on current connections
			if (loadConnections + a) > poolConnectionsAvg*b {
				c.logger.Debugf("increasing pool size: %d -> %d, avg pool conn: %d, avg load conn: %d", newPoolSize, newPoolSize+1, poolConnectionsAvg, loadConnections)
				newPoolSize++

				// Add a new connection to the pool
				go c.tunnelDialer()
			} else if float64(loadConnections+x) < float64(poolConnectionsAvg)*y && newPoolSize > c.config.ConnPoolSize {
				c.logger.Debugf("decreasing pool size: %d -> %d, avg pool conn: %d, avg load conn: %d", newPoolSize, newPoolSize-1, poolConnectionsAvg, loadConnections)
				newPoolSize--

				// send a signal to controlFlow
				c.controlFlow <- struct{}{}
			}
		}
	}
}

func (c *HttpTransport) channelHandler() {
	msgChan := make(chan byte, 1000)

	// Goroutine to handle the blocking read
	go func() {
		for {
			select {
			case <-c.ctx.Done():
				return
			default:
				msg, err := utils.ReceiveBinaryByte(c.controlChannel)
				if err != nil {
					if c.cancel != nil {
						c.logger.Error("failed to read from channel connection. ", err)
						go c.Restart()
					}
					return
				}
				msgChan <- msg
			}
		}
	}()

	// Main loop to listen for context cancellation or received messages
	for {
		select {
		case <-c.ctx.Done():
			_ = utils.SendBinaryByte(c.controlChannel, utils.SG_Closed)
			return

		case msg := <-msgChan:
			switch msg {
			case utils.SG_Chan:
				atomic.AddInt32(&c.loadConnections, 1)
				select {
				case <-c.controlFlow: // Do nothing

				default:
					c.logger.Debug("channel signal received, initiating tunnel dialer")
					go c.tunnelDialer()
				}

			case utils.SG_HB:
				c.logger.Debug("heartbeat signal received successfully")
				// send heartbeat back
				err := utils.SendBinaryByte(c.controlChannel, utils.SG_HB)
				if err != nil {
					c.logger.Errorf("failed to send heartbeat: %v", msg)
					go c.Restart()
					return
				}
				c.logger.Trace("heartbeat signal sent successfully")

			case utils.SG_Closed:
				c.logger.Warn("control channel has been closed by the server")
				go c.Restart()
				return

			default:
				c.logger.Errorf("unexpected response from channel: %v", msg)
				go c.Restart()
				return
			}
		}
	}
}

func (c *HttpTransport) tunnelDialer() {
	c.logger.Debugf("initiating new http tunnel connection to address %s", c.config.RemoteAddr)

	// Dial to the tunnel server via HTTP
	tunnelConn, err := network.HttpDialer(c.ctx, c.config.RemoteAddr, c.config.EdgeIP, "/tunnel", c.config.DialTimeOut, c.config.KeepAlive, c.config.Nodelay, c.config.Token, c.config.Mode, 3, 0, 0)
	if err != nil {
		c.logger.Errorf("tunnel server dialer: %v", err)
		return
	}

	// Increment active connections counter
	atomic.AddInt32(&c.poolConnections, 1)

	// Receive the remote address from the tunnel server using the binary protocol
	remoteAddr, transport, err := utils.ReceiveBinaryTransportString(tunnelConn)

	// Decrement active connections
	atomic.AddInt32(&c.poolConnections, -1)

	if err != nil {
		c.logger.Debugf("failed to receive port from tunnel connection %s: %v", tunnelConn.RemoteAddr().String(), err)
		tunnelConn.Close()
		return
	}

	// Extract the port from the received address
	port, resolvedAddr, err := network.ResolveRemoteAddr(remoteAddr)
	if err != nil {
		c.logger.Infof("failed to resolve remote port: %v", err)
		tunnelConn.Close()
		return
	}

	switch transport {
	case utils.SG_TCP:
		c.localDialer(tunnelConn, resolvedAddr, port)
	default:
		c.logger.Error("undefined transport. close the connection.")
		tunnelConn.Close()
	}
}

func (c *HttpTransport) localDialer(tunnelConn net.Conn, remoteAddr string, port int) {
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
