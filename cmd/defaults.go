package cmd

import (
	"github.com/sahmadiut/backhaul/internal/config"

	"github.com/sirupsen/logrus"
)

const ( // Default values
	defaultTransport      = config.TCP
	defaultToken          = "sahmadiut"
	defaultChannelSize    = 2048
	defaultRetryInterval  = 1 // only for client
	defaultConnectionPool = 8
	defaultLogLevel       = "info"
	defaultMuxSession     = 1
	defaultKeepAlive      = 20
	// related to smux
	defaultMuxVersion       = 1
	defaultMaxFrameSize     = 32768   // 32KB
	defaultMaxReceiveBuffer = 4194304 // 4MB
	defaultMaxStreamBuffer  = 65536   // 256KB
	defaultSnifferLog       = "backhaul.json"
	deafultHeartbeat        = 20 // 20 seconds
)

func applyDefaults(cfg *config.Config) {
	// Transport
	switch cfg.Server.Transport {
	case config.TCP, config.TCPMUX, config.WS, config.WSS: // valid values
	case "":
		cfg.Server.Transport = defaultTransport
	default:
		logger.Warnf("invalid transport value '%s' for server, defaulting to '%s'", cfg.Server.Transport, defaultTransport)
		cfg.Server.Transport = defaultTransport
	}

	switch cfg.Client.Transport {
	case config.TCP, config.TCPMUX, config.WS, config.WSS: //valid values
	case "":
		cfg.Client.Transport = defaultTransport
	default:
		logger.Warnf("invalid transport value '%s' for client, defaulting to '%s'", cfg.Client.Transport, defaultTransport)
		cfg.Client.Transport = defaultTransport
	}

	// Token
	if cfg.Server.Token == "" {
		cfg.Server.Token = defaultToken
	}
	if cfg.Client.Token == "" {
		cfg.Client.Token = defaultToken
	}

	// Nodelay default is false if not valid value found

	// Channel size
	if cfg.Server.ChannelSize <= 0 {
		cfg.Server.ChannelSize = defaultChannelSize
	}

	// Loglevel
	if _, err := logrus.ParseLevel(cfg.Client.LogLevel); err != nil {
		cfg.Client.LogLevel = defaultLogLevel
	}

	if _, err := logrus.ParseLevel(cfg.Server.LogLevel); err != nil {
		cfg.Server.LogLevel = defaultLogLevel
	}

	// Retry interval
	if cfg.Client.RetryInterval <= 0 {
		cfg.Client.RetryInterval = defaultRetryInterval
	}

	// Connection pool
	if cfg.Server.ConnectionPool <= 0 {
		cfg.Server.ConnectionPool = defaultConnectionPool
	}

	// Mux Session
	if cfg.Server.MuxSession <= 0 {
		cfg.Server.MuxSession = defaultMuxSession
	}
	if cfg.Client.MuxSession <= 0 {
		cfg.Client.MuxSession = defaultMuxSession
	}

	// PPROF default is false if not valid value found

	// keep alive
	if cfg.Server.Keepalive <= 0 {
		cfg.Server.Keepalive = defaultKeepAlive
	}
	if cfg.Client.Keepalive <= 0 {
		cfg.Client.Keepalive = defaultKeepAlive
	}

	// Mux version
	if cfg.Server.MuxVersion <= 0 || cfg.Server.MuxVersion > 2 {
		cfg.Server.MuxVersion = defaultMuxVersion
	}
	if cfg.Client.MuxVersion <= 0 || cfg.Client.MuxVersion > 2 {
		cfg.Client.MuxVersion = defaultMuxVersion
	}
	// MaxFrameSize
	if cfg.Server.MaxFrameSize <= 0 {
		cfg.Server.MaxFrameSize = defaultMaxFrameSize
	}
	if cfg.Client.MaxFrameSize <= 0 {
		cfg.Client.MaxFrameSize = defaultMaxFrameSize
	}
	// MaxReceiveBuffer
	if cfg.Server.MaxReceiveBuffer <= 0 {
		cfg.Server.MaxReceiveBuffer = defaultMaxReceiveBuffer
	}
	if cfg.Client.MaxReceiveBuffer <= 0 {
		cfg.Client.MaxReceiveBuffer = defaultMaxReceiveBuffer
	}
	// MaxStreamBuffer
	if cfg.Server.MaxStreamBuffer <= 0 {
		cfg.Server.MaxStreamBuffer = defaultMaxStreamBuffer
	}
	if cfg.Client.MaxStreamBuffer <= 0 {
		cfg.Client.MaxStreamBuffer = defaultMaxStreamBuffer
	}
	// WebPort returns 0 if not exists

	// SnifferLog
	if cfg.Server.SnifferLog == "" {
		cfg.Server.SnifferLog = defaultSnifferLog
	}
	if cfg.Client.SnifferLog == "" {
		cfg.Client.SnifferLog = defaultSnifferLog
	}
	// Heartbeat
	if cfg.Server.Heartbeat < 1 { // Minimum accepted interval is 1 second
		cfg.Server.Heartbeat = deafultHeartbeat
	}

}
