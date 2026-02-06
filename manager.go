package udpbara

import (
	"context"
	"fmt"
	"sync"
)

// Manager manages multiple named tunnels through different SOCKS5 proxies.
// It provides a higher-level API for applications that need to maintain
// connections through multiple proxy endpoints simultaneously.
// All methods are safe for concurrent use.
type Manager struct {
	mu      sync.RWMutex
	tunnels map[string]*Tunnel
	config  Config
}

// NewManager creates a new tunnel manager with optional configuration.
// If no config is provided, DefaultConfig() is used for all tunnels.
func NewManager(config ...Config) *Manager {
	cfg := DefaultConfig()
	if len(config) > 0 {
		cfg = config[0]
	}
	return &Manager{
		tunnels: make(map[string]*Tunnel),
		config:  cfg,
	}
}

// AddTunnel creates and connects a named tunnel through a SOCKS5 proxy.
// Returns an error if a tunnel with the same name already exists.
func (m *Manager) AddTunnel(name, proxyURL string) (*Tunnel, error) {
	return m.AddTunnelContext(context.Background(), name, proxyURL)
}

// AddTunnelContext is like AddTunnel but respects context cancellation.
func (m *Manager) AddTunnelContext(ctx context.Context, name, proxyURL string) (*Tunnel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.tunnels[name]; exists {
		return nil, fmt.Errorf("tunnel %q already exists", name)
	}

	tunnel, err := NewTunnel(proxyURL, m.config)
	if err != nil {
		return nil, err
	}

	if err := tunnel.ConnectContext(ctx); err != nil {
		return nil, err
	}

	m.tunnels[name] = tunnel
	return tunnel, nil
}

// GetTunnel returns a named tunnel, or an error if not found.
func (m *Manager) GetTunnel(name string) (*Tunnel, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tunnel, exists := m.tunnels[name]
	if !exists {
		return nil, fmt.Errorf("tunnel %q not found", name)
	}
	return tunnel, nil
}

// Dial creates a connection through a named tunnel to a target.
// If the tunnel doesn't exist, it creates and connects one using the given proxyURL.
// If the tunnel already exists, proxyURL is ignored.
func (m *Manager) Dial(name, proxyURL, target string) (*Connection, error) {
	return m.DialContext(context.Background(), name, proxyURL, target)
}

// DialContext is like Dial but respects context cancellation.
func (m *Manager) DialContext(ctx context.Context, name, proxyURL, target string) (*Connection, error) {
	m.mu.Lock()
	tunnel, exists := m.tunnels[name]
	if !exists {
		var err error
		tunnel, err = NewTunnel(proxyURL, m.config)
		if err != nil {
			m.mu.Unlock()
			return nil, err
		}
		if err := tunnel.ConnectContext(ctx); err != nil {
			m.mu.Unlock()
			return nil, err
		}
		m.tunnels[name] = tunnel
	}
	m.mu.Unlock()

	return tunnel.DialContext(ctx, target)
}

// RemoveTunnel stops and removes a named tunnel. All connections through
// the tunnel are closed. Returns an error if the tunnel is not found.
func (m *Manager) RemoveTunnel(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	tunnel, exists := m.tunnels[name]
	if !exists {
		return fmt.Errorf("tunnel %q not found", name)
	}

	tunnel.Close()
	delete(m.tunnels, name)
	return nil
}

// List returns all active tunnel names.
func (m *Manager) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.tunnels))
	for name := range m.tunnels {
		names = append(names, name)
	}
	return names
}

// CloseAll stops and removes all tunnels managed by this Manager.
// All connections through all tunnels are closed.
func (m *Manager) CloseAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for name, tunnel := range m.tunnels {
		tunnel.Close()
		delete(m.tunnels, name)
	}
}

// Dial is a convenience function that creates a tunnel and dials a target in one call.
// Returns a *Connection with a real *net.UDPConn for quic-go compatibility.
// The caller must close the returned Connection when done.
//
// Example:
//
//	conn, err := udpbara.Dial("socks5h://user:pass@proxy.com:10000", "target.com:443")
//	if err != nil { ... }
//	defer conn.Close()
func Dial(proxyURL, target string, config ...Config) (*Connection, error) {
	return DialContext(context.Background(), proxyURL, target, config...)
}

// DialContext is a convenience function like Dial but respects context cancellation.
// The context is used for both the proxy connection and target DNS resolution.
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
//	defer cancel()
//	conn, err := udpbara.DialContext(ctx, "socks5h://user:pass@proxy:10000", "target.com:443")
func DialContext(ctx context.Context, proxyURL, target string, config ...Config) (*Connection, error) {
	cfg := DefaultConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	tunnel, err := NewTunnel(proxyURL, cfg)
	if err != nil {
		return nil, err
	}

	if err := tunnel.ConnectContext(ctx); err != nil {
		return nil, err
	}

	conn, err := tunnel.DialContext(ctx, target)
	if err != nil {
		tunnel.Close()
		return nil, err
	}
	// Mark this connection as owning the tunnel so Close() cleans up everything.
	conn.ownsTunnel = tunnel
	return conn, nil
}
