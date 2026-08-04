package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/sahmadiut/backhaul/config"
	"github.com/sahmadiut/backhaul/internal/client"

	"github.com/sahmadiut/backhaul/internal/server"
	"github.com/sahmadiut/backhaul/internal/utils"

	"github.com/BurntSushi/toml"
)

var (
	logger = utils.NewLogger("info")
)

func Run(configPath string, version string, ctx context.Context) {
	// Load and parse the configuration file
	cfg, err := loadConfig(configPath)
	if err != nil {
		logger.Fatalf("failed to load configuration: %v", err)
	}

	// Apply default values to the configuration
	applyDefaults(cfg)

	configType := ""
	if cfg.Server.BindAddr != "" {
		configType = "server"
	} else if cfg.Client.RemoteAddr != "" {
		configType = "client"
	} else {
		logger.Fatalf("neither server nor client configuration is properly set.")
	}

	// Print startup separator and configuration summary
	printStartupBanner(cfg, configType, configPath, version)

	// Determine whether to run as a server or client
	switch configType {
	case "server":
		// Apply temporary TCP optimizations at startup
		if !cfg.Server.SkipOptz {
			ApplyTCPTuning()
		}

		srv := server.NewServer(&cfg.Server, ctx) // server
		go srv.Start()

		// Wait for shutdown signal
		<-ctx.Done()
		srv.Stop()
		logger.Println("shutting down server...")
	case "client":
		// Apply temporary TCP optimizations at startup
		if !cfg.Client.SkipOptz {
			ApplyTCPTuning()
		}

		clnt := client.NewClient(&cfg.Client, ctx) // client
		go clnt.Start()

		// Wait for shutdown signal
		<-ctx.Done()
		clnt.Stop()
		logger.Println("shutting down client...")

	default:
		logger.Fatalf("neither server nor client configuration is properly set.")

	}
}

// loadConfig loads and parses the TOML configuration file.
func loadConfig(configPath string) (*config.Config, error) {
	var cfg config.Config
	if _, err := toml.DecodeFile(configPath, &cfg); err != nil {
		return &cfg, err
	}
	return &cfg, nil
}

// printStartupBanner prints a visual separator and configuration summary at startup.
func printStartupBanner(cfg *config.Config, mode string, configPath string, version string) {
	separator := strings.Repeat("─", 60)

	fmt.Fprintf(logger.Out, "\n\033[36m%s\033[0m\n", separator)
	fmt.Fprintf(logger.Out, "\033[1;36m  Backhaul Starting (%s)\033[0m\n", version)
	fmt.Fprintf(logger.Out, "\033[36m%s\033[0m\n\n", separator)

	switch mode {
	case "server":
		s := &cfg.Server
		logger.Infof("Mode:        server")
		logger.Infof("Config:      %s", configPath)
		logger.Infof("Transport:   %s", s.Transport)
		logger.Infof("Bind Addr:   %s", s.BindAddr)
		logger.Infof("Ports:       %s", formatPorts(s.Ports))
		logger.Infof("Log Level:   %s", s.LogLevel)
		logger.Infof("Keepalive:   %ds | Heartbeat: %ds", s.Keepalive, s.Heartbeat)
		logger.Infof("Channel:     %d | Nodelay: %v", s.ChannelSize, s.Nodelay)

		if isMuxTransport(s.Transport) {
			logger.Infof("Mux:         sessions=%d version=%d con=%d", s.MuxSession, s.MuxVersion, s.MuxCon)
			logger.Infof("Mux Buffers: frame=%d recv=%d stream=%d", s.MaxFrameSize, s.MaxReceiveBuffer, s.MaxStreamBuffer)
		}

		if s.Sniffer {
			logger.Infof("Sniffer:     enabled (log: %s)", s.SnifferLog)
		}
		if s.WebPort > 0 {
			logger.Infof("Web Port:    %d", s.WebPort)
		}
		if s.PPROF {
			logger.Infof("PProf:       enabled (port 6060)")
		}
		if s.AcceptUDP {
			logger.Infof("Accept UDP:  enabled")
		}
		if s.ProxyProtocol {
			logger.Infof("Proxy Proto: enabled")
		}
		if s.TLSCertFile != "" {
			logger.Infof("TLS:         cert=%s key=%s", s.TLSCertFile, s.TLSKeyFile)
		}

	case "client":
		c := &cfg.Client
		logger.Infof("Mode:        client")
		logger.Infof("Config:      %s", configPath)
		logger.Infof("Transport:   %s", c.Transport)
		logger.Infof("Remote Addr: %s", c.RemoteAddr)
		logger.Infof("Log Level:   %s", c.LogLevel)
		logger.Infof("Keepalive:   %ds | Retry: %ds | Dial Timeout: %ds", c.Keepalive, c.RetryInterval, c.DialTimeout)
		logger.Infof("Conn Pool:   %d | Nodelay: %v", c.ConnectionPool, c.Nodelay)

		if isMuxTransport(c.Transport) {
			logger.Infof("Mux:         sessions=%d version=%d", c.MuxSession, c.MuxVersion)
			logger.Infof("Mux Buffers: frame=%d recv=%d stream=%d", c.MaxFrameSize, c.MaxReceiveBuffer, c.MaxStreamBuffer)
		}

		if c.Sniffer {
			logger.Infof("Sniffer:     enabled (log: %s)", c.SnifferLog)
		}
		if c.WebPort > 0 {
			logger.Infof("Web Port:    %d", c.WebPort)
		}
		if c.PPROF {
			logger.Infof("PProf:       enabled (port 6061)")
		}
		if c.AggressivePool {
			logger.Infof("Aggr. Pool:  enabled")
		}
		if c.EdgeIP != "" {
			logger.Infof("Edge IP:     %s", c.EdgeIP)
		}
	}

	fmt.Fprintf(logger.Out, "\033[36m%s\033[0m\n\n", separator)
}

// formatPorts returns a compact string representation of port mappings.
func formatPorts(ports []string) string {
	if len(ports) == 0 {
		return "(none)"
	}
	if len(ports) <= 5 {
		return strings.Join(ports, ", ")
	}
	return fmt.Sprintf("%s ... (%d total)", strings.Join(ports[:3], ", "), len(ports))
}

// isMuxTransport returns true if the transport uses multiplexing.
func isMuxTransport(t config.TransportType) bool {
	return t == config.TCPMUX || t == config.WSMUX || t == config.WSSMUX
}

