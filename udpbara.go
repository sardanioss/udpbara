// Package udpbara provides userspace UDP relay through SOCKS5 proxies.
//
// It enables QUIC/HTTP3 and other UDP protocols to work through SOCKS5 proxies
// that require hostname-based authentication, without requiring root access,
// TUN interfaces, or system-wide routing changes.
//
// Each tunnel maintains a single SOCKS5 UDP ASSOCIATE session and can multiplex
// multiple target destinations through the same proxy connection.
package udpbara

import (
	"fmt"
	"net/url"
)

// Config holds configuration for a tunnel.
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

// ParseProxyURL parses a SOCKS5 proxy URL and returns components.
// Accepted formats: socks5://user:pass@host:port, socks5h://user:pass@host:port
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
	addr = u.Host
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	return addr, user, pass, nil
}
