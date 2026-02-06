package udpbara

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Tunnel maintains a SOCKS5 UDP ASSOCIATE session through a single proxy.
// It can create multiple connections for different targets,
// all sharing the same proxy connection.
type Tunnel struct {
	proxyAddr string
	proxyUser string
	proxyPass string
	config    Config

	mu         sync.Mutex
	controlTCP net.Conn     // SOCKS5 control TCP connection
	relayAddr  *net.UDPAddr // SOCKS5 relay UDP address
	remoteUDP  *net.UDPConn // UDP socket to the SOCKS5 relay

	// Active connections keyed by address (both hostname and resolved IPs).
	// Multiple keys can point to the same []*tunnelConn slice.
	connsMu sync.RWMutex
	conns   map[string][]*tunnelConn
	// allConns is a flat list for fallback broadcast when key lookup fails.
	allConns []*tunnelConn

	running  atomic.Bool
	closeCh  chan struct{}

	// Stats
	pktsSent  atomic.Uint64
	pktsRecv  atomic.Uint64
	bytesSent atomic.Uint64
	bytesRecv atomic.Uint64
}

// TunnelStats contains tunnel statistics.
type TunnelStats struct {
	PacketsSent uint64
	PacketsRecv uint64
	BytesSent   uint64
	BytesRecv   uint64
}

// Connection holds the resources for a single target connection through a tunnel.
// Use PacketConn() to get the *net.UDPConn for quic-go, and RelayAddr() for the
// address to pass to quic.Transport.Dial().
type Connection struct {
	conn     *tunnelConn
	ownsTunnel *Tunnel // non-nil if this Connection owns the tunnel lifecycle (from top-level Dial)
}

// PacketConn returns the real *net.UDPConn for use with quic-go.
func (c *Connection) PacketConn() *net.UDPConn {
	return c.conn.PacketConn()
}

// RelayAddr returns the address that QUIC should dial to.
func (c *Connection) RelayAddr() *net.UDPAddr {
	return c.conn.RelayAddr()
}

// Tunnel returns the underlying Tunnel this connection belongs to.
// Useful for accessing Stats() on connections created via the top-level Dial().
func (c *Connection) Tunnel() *Tunnel {
	return c.conn.tunnel
}

// Close shuts down this connection. If this Connection was created by the
// top-level Dial() function, it also closes the underlying tunnel.
func (c *Connection) Close() error {
	err := c.conn.Close()
	if c.ownsTunnel != nil {
		c.ownsTunnel.Close()
	}
	return err
}

// NewTunnel creates a new tunnel through a SOCKS5 proxy.
// Call Connect() to establish the SOCKS5 session, then Dial() to create connections.
func NewTunnel(proxyURL string, config ...Config) (*Tunnel, error) {
	addr, user, pass, err := ParseProxyURL(proxyURL)
	if err != nil {
		return nil, err
	}

	cfg := DefaultConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	return &Tunnel{
		proxyAddr: addr,
		proxyUser: user,
		proxyPass: pass,
		config:    cfg,
		conns:     make(map[string][]*tunnelConn),
		closeCh:   make(chan struct{}),
	}, nil
}

// Connect establishes the SOCKS5 UDP ASSOCIATE session.
func (t *Tunnel) Connect() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.running.Load() {
		return nil
	}

	if err := t.connect(); err != nil {
		return err
	}

	t.running.Store(true)
	go t.readLoop()
	go t.monitorControl()

	return nil
}

// connect performs the actual SOCKS5 handshake and UDP ASSOCIATE.
func (t *Tunnel) connect() error {
	timeout := time.Duration(t.config.ConnectTimeout) * time.Second
	tcpConn, err := net.DialTimeout("tcp", t.proxyAddr, timeout)
	if err != nil {
		return fmt.Errorf("tcp connect: %w", err)
	}

	if t.config.TCPKeepAlive {
		if tc, ok := tcpConn.(*net.TCPConn); ok {
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(time.Duration(t.config.TCPKeepAlivePeriod) * time.Second)
		}
	}

	if err := socks5Handshake(tcpConn, t.proxyUser, t.proxyPass); err != nil {
		tcpConn.Close()
		return fmt.Errorf("socks5 handshake: %w", err)
	}

	relayAddr, err := socks5UDPAssociate(tcpConn)
	if err != nil {
		tcpConn.Close()
		return fmt.Errorf("udp associate: %w", err)
	}

	remoteUDP, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		tcpConn.Close()
		return fmt.Errorf("udp dial: %w", err)
	}

	remoteUDP.SetReadBuffer(t.config.ReadBufferSize)
	remoteUDP.SetWriteBuffer(t.config.WriteBufferSize)

	t.controlTCP = tcpConn
	t.relayAddr = relayAddr
	t.remoteUDP = remoteUDP

	return nil
}

// Dial creates a new connection through this tunnel to the specified target.
// Returns a Connection with a real *net.UDPConn (fully compatible with quic-go).
//
// target format: "host:port" (e.g., "www.example.com:443")
func (t *Tunnel) Dial(target string) (*Connection, error) {
	if !t.running.Load() {
		return nil, fmt.Errorf("tunnel not connected")
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target %q: %w", target, err)
	}
	if len(host) > 255 {
		return nil, fmt.Errorf("hostname too long (%d bytes, max 255)", len(host))
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port in %q: %w", target, err)
	}

	socks5Header := buildSOCKS5UDPHeader(host, port)

	conn, err := newTunnelConn(t, target, socks5Header)
	if err != nil {
		return nil, fmt.Errorf("create conn: %w", err)
	}

	// Register under hostname:port key
	t.connsMu.Lock()
	t.conns[target] = append(t.conns[target], conn)
	t.allConns = append(t.allConns, conn)

	// Also register under resolved IP:port keys so readLoop can match
	// SOCKS5 responses that come back with the server's actual IP.
	if ip := net.ParseIP(host); ip == nil {
		// host is a hostname, resolve it
		if ips, err := net.LookupIP(host); err == nil {
			for _, resolved := range ips {
				ipKey := fmt.Sprintf("%s:%s", resolved.String(), portStr)
				t.conns[ipKey] = append(t.conns[ipKey], conn)
			}
		}
	}
	t.connsMu.Unlock()

	return &Connection{conn: conn}, nil
}

// Stats returns tunnel statistics.
func (t *Tunnel) Stats() TunnelStats {
	return TunnelStats{
		PacketsSent: t.pktsSent.Load(),
		PacketsRecv: t.pktsRecv.Load(),
		BytesSent:   t.bytesSent.Load(),
		BytesRecv:   t.bytesRecv.Load(),
	}
}

// Close shuts down the tunnel and all connections.
func (t *Tunnel) Close() error {
	if !t.running.CompareAndSwap(true, false) {
		return nil
	}

	close(t.closeCh)

	// Use allConns to close each connection exactly once (conns map has
	// duplicate entries under hostname and IP keys).
	t.connsMu.Lock()
	for _, c := range t.allConns {
		c.closeMu.Lock()
		if !c.closed {
			c.closed = true
			close(c.closeCh)
			c.appConn.Close()
			c.relayConn.Close()
		}
		c.closeMu.Unlock()
	}
	t.conns = make(map[string][]*tunnelConn)
	t.allConns = nil
	t.connsMu.Unlock()

	t.mu.Lock()
	if t.remoteUDP != nil {
		t.remoteUDP.Close()
	}
	if t.controlTCP != nil {
		t.controlTCP.Close()
	}
	t.mu.Unlock()

	return nil
}

// readLoop continuously reads from the SOCKS5 relay and dispatches to connections.
func (t *Tunnel) readLoop() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-t.closeCh:
			return
		default:
		}

		t.remoteUDP.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := t.remoteUDP.Read(buf)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			select {
			case <-t.closeCh:
				return
			default:
				continue
			}
		}

		payload, sourceHost, sourcePort, err := parseSOCKS5UDPPacket(buf[:n])
		if err != nil {
			continue
		}

		t.pktsRecv.Add(1)
		t.bytesRecv.Add(uint64(len(payload)))

		// Dispatch to matching connections by source address key.
		// The SOCKS5 relay returns the actual server IP, so we try that first.
		// If no match (e.g., DNS returned a different IP than we resolved),
		// fall back to broadcasting to all connections on this tunnel.
		sourceKey := fmt.Sprintf("%s:%d", sourceHost, sourcePort)
		t.connsMu.RLock()
		conns := t.conns[sourceKey]
		if len(conns) == 0 {
			// Fallback: broadcast to all active connections
			conns = t.allConns
		}
		for _, c := range conns {
			pktCopy := make([]byte, len(payload))
			copy(pktCopy, payload)
			c.deliverPacket(pktCopy)
		}
		t.connsMu.RUnlock()
	}
}

// monitorControl watches the TCP control connection for drops.
func (t *Tunnel) monitorControl() {
	buf := make([]byte, 1)
	for {
		select {
		case <-t.closeCh:
			return
		default:
		}

		t.controlTCP.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, err := t.controlTCP.Read(buf)
		if err != nil {
			if isTimeout(err) {
				continue
			}

			if t.config.AutoReconnect && t.running.Load() {
				t.reconnect()
			} else {
				t.Close()
			}
			return
		}
	}
}

// reconnect re-establishes the SOCKS5 session.
func (t *Tunnel) reconnect() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.remoteUDP != nil {
		t.remoteUDP.Close()
	}
	if t.controlTCP != nil {
		t.controlTCP.Close()
	}

	for attempt := 0; attempt < 5; attempt++ {
		if !t.running.Load() {
			return
		}

		if err := t.connect(); err != nil {
			time.Sleep(time.Duration(1<<uint(attempt)) * time.Second)
			continue
		}

		go t.readLoop()
		go t.monitorControl()
		return
	}

	t.running.Store(false)
}
