// Package udpbara provides userspace UDP relay through SOCKS5 proxies.
//
// It enables QUIC/HTTP3 and other UDP protocols to work through SOCKS5 proxies
// that require hostname-based authentication, without requiring root access,
// TUN interfaces, or system-wide routing changes.
//
// Each tunnel maintains a single SOCKS5 UDP ASSOCIATE session and can multiplex
// multiple target destinations through the same proxy connection. Connections
// expose a real *net.UDPConn for full compatibility with quic-go (OOB/ECN support).
//
// Basic usage:
//
//	conn, err := udpbara.Dial("socks5h://user:pass@proxy:10000", "target.com:443")
//	if err != nil { log.Fatal(err) }
//	defer conn.Close()
//
//	transport := &quic.Transport{Conn: conn.PacketConn()}
//	quicConn, err := transport.Dial(ctx, conn.RelayAddr(), tlsConfig, quicConfig)
package udpbara

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
)

// Logger is an optional logging interface for tunnel events.
// Implement this to integrate with your application's logging framework.
type Logger interface {
	// Debug logs a debug-level message (packet dispatch, connection registration).
	Debug(msg string, args ...any)
	// Info logs an info-level message (connect, disconnect, reconnect).
	Info(msg string, args ...any)
	// Error logs an error-level message (connection failures, protocol errors).
	Error(msg string, args ...any)
}

// Config holds configuration for a tunnel. All fields have sensible defaults
// via DefaultConfig(). Zero-value fields will not override defaults when passed
// to NewTunnel or Dial — use DefaultConfig() and modify specific fields instead.
type Config struct {
	// ReadBufferSize is the UDP socket read buffer size in bytes.
	// Default: 7MB (recommended for QUIC).
	ReadBufferSize int

	// WriteBufferSize is the UDP socket write buffer size in bytes.
	// Default: 7MB (recommended for QUIC).
	WriteBufferSize int

	// TCPKeepAlive enables TCP keepalive on the SOCKS5 control connection.
	// Default: true.
	TCPKeepAlive bool

	// TCPKeepAlivePeriod is the interval between TCP keepalive probes in seconds.
	// Default: 30.
	TCPKeepAlivePeriod int

	// ConnectTimeout is the timeout for connecting to the SOCKS5 proxy in seconds.
	// Default: 10.
	ConnectTimeout int

	// AutoReconnect enables automatic reconnection when the TCP control drops.
	// Default: true.
	AutoReconnect bool

	// Logger is an optional logger for tunnel events.
	// If nil, no logging is performed. Default: nil.
	Logger Logger
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		ReadBufferSize:     7 * 1024 * 1024,
		WriteBufferSize:    7 * 1024 * 1024,
		TCPKeepAlive:       true,
		TCPKeepAlivePeriod: 30,
		ConnectTimeout:     10,
		AutoReconnect:      true,
	}
}

// ParseProxyURL parses a SOCKS5 proxy URL and returns its components.
// Accepted formats:
//
//	socks5://user:pass@host:port
//	socks5h://user:pass@host:port
//	socks5://host:port  (no auth)
//
// Both socks5 and socks5h schemes are accepted (udpbara always preserves
// hostnames in SOCKS5 UDP headers regardless of scheme).
func ParseProxyURL(proxyURL string) (addr, user, pass string, err error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return "", "", "", fmt.Errorf("invalid proxy URL: %w", err)
	}
	if u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return "", "", "", fmt.Errorf("unsupported scheme %q, need socks5 or socks5h", u.Scheme)
	}
	if u.Host == "" {
		return "", "", "", fmt.Errorf("missing proxy host")
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return "", "", "", fmt.Errorf("proxy URL must include a port (e.g. socks5://host:1080): %w", err)
	}
	if host == "" {
		return "", "", "", fmt.Errorf("missing proxy host")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", "", "", fmt.Errorf("invalid proxy port %q: must be 1–65535", portStr)
	}
	addr = u.Host
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	return addr, user, pass, nil
}
