package udpbara

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Tunnel maintains a SOCKS5 UDP ASSOCIATE session through a single proxy.
// It can create multiple connections for different targets, all sharing the
// same proxy connection and UDP relay.
//
// A Tunnel handles the full SOCKS5 lifecycle: TCP control connection,
// authentication, UDP relay setup, packet dispatch, and automatic reconnection.
// Use NewTunnel() to create, Connect() to establish, and Dial() to create connections.
type Tunnel struct {
	proxyAddr string
	proxyUser string
	proxyPass string
	config    Config

	mu         sync.Mutex
	controlTCP net.Conn     // SOCKS5 control TCP connection
	relayAddr  *net.UDPAddr // SOCKS5 relay UDP address
	remoteUDP  atomic.Pointer[net.UDPConn] // UDP socket to the SOCKS5 relay (atomic for lock-free hot path)

	// Active connections keyed by address (both hostname and resolved IPs).
	// Multiple keys can point to the same []*tunnelConn slice.
	connsMu sync.RWMutex
	conns   map[string][]*tunnelConn
	// allConns is a flat list for fallback broadcast when key lookup fails.
	allConns []*tunnelConn

	running  atomic.Bool
	closeCh  chan struct{}

	// Logger (nil = no logging)
	logger Logger

	// Stats
	pktsSent  atomic.Uint64
	pktsRecv  atomic.Uint64
	bytesSent atomic.Uint64
	bytesRecv atomic.Uint64
}

// Stats contains packet and byte counters. Used for both tunnel-level
// and connection-level statistics.
type Stats struct {
	PacketsSent uint64
	PacketsRecv uint64
	BytesSent   uint64
	BytesRecv   uint64
}

// TunnelStats is an alias for Stats for backward compatibility.
type TunnelStats = Stats

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
// Useful for accessing tunnel-level Stats() on connections created via the top-level Dial().
func (c *Connection) Tunnel() *Tunnel {
	return c.conn.tunnel
}

// Target returns the target address this connection was dialed to (e.g., "example.com:443").
func (c *Connection) Target() string {
	return c.conn.target
}

// Stats returns per-connection packet and byte counters.
func (c *Connection) Stats() Stats {
	return Stats{
		PacketsSent: c.conn.pktsSent.Load(),
		PacketsRecv: c.conn.pktsRecv.Load(),
		BytesSent:   c.conn.bytesSent.Load(),
		BytesRecv:   c.conn.bytesRecv.Load(),
	}
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
		logger:    cfg.Logger,
		conns:     make(map[string][]*tunnelConn),
		closeCh:   make(chan struct{}),
	}, nil
}

// log helper methods — safe to call when logger is nil.
func (t *Tunnel) logDebug(msg string, args ...any) {
	if t.logger != nil {
		t.logger.Debug(msg, args...)
	}
}

func (t *Tunnel) logInfo(msg string, args ...any) {
	if t.logger != nil {
		t.logger.Info(msg, args...)
	}
}

func (t *Tunnel) logError(msg string, args ...any) {
	if t.logger != nil {
		t.logger.Error(msg, args...)
	}
}

// Connect establishes the SOCKS5 UDP ASSOCIATE session with the proxy.
// This performs the TCP connection, SOCKS5 handshake, and UDP relay setup.
// It is safe to call multiple times — subsequent calls are no-ops if already connected.
// After Connect returns, call Dial() to create connections to targets.
func (t *Tunnel) Connect() error {
	return t.ConnectContext(context.Background())
}

// ConnectContext is like Connect but respects context cancellation and deadlines.
// Returns context.DeadlineExceeded or context.Canceled if the context expires
// before the connection is established.
func (t *Tunnel) ConnectContext(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.running.Load() {
		return nil
	}

	// Check context before attempting connection
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := t.connectContext(ctx); err != nil {
		t.logError("connect failed", "proxy", t.proxyAddr, "error", err)
		return err
	}

	t.running.Store(true)
	go t.readLoop()
	go t.monitorControl()

	t.logInfo("tunnel connected", "proxy", t.proxyAddr, "relay", t.relayAddr)
	return nil
}

// connect performs the actual SOCKS5 handshake and UDP ASSOCIATE.
func (t *Tunnel) connect() error {
	return t.connectContext(context.Background())
}

// connectContext performs the SOCKS5 handshake with context support.
func (t *Tunnel) connectContext(ctx context.Context) error {
	timeout := time.Duration(t.config.ConnectTimeout) * time.Second

	// Use context deadline if it's sooner than ConnectTimeout
	dialer := &net.Dialer{Timeout: timeout}
	tcpConn, err := dialer.DialContext(ctx, "tcp", t.proxyAddr)
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
	t.remoteUDP.Store(remoteUDP)

	return nil
}

// Dial creates a new connection through this tunnel to the specified target.
// Returns a Connection with a real *net.UDPConn (fully compatible with quic-go).
//
// The target format is "host:port" (e.g., "www.example.com:443"). Hostnames are
// preserved in the SOCKS5 UDP header for proxy-side DNS resolution and auth.
// The connection is also registered under resolved IP keys for response dispatch.
//
// Multiple connections to different targets can share the same tunnel.
func (t *Tunnel) Dial(target string) (*Connection, error) {
	return t.DialContext(context.Background(), target)
}

// DialContext is like Dial but respects context cancellation.
// The context is used for DNS resolution of the target hostname.
func (t *Tunnel) DialContext(ctx context.Context, target string) (*Connection, error) {
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
		t.logError("dial failed", "target", target, "error", err)
		return nil, fmt.Errorf("create conn: %w", err)
	}

	t.logDebug("connection created", "target", target, "app", conn.PacketConn().LocalAddr(), "relay", conn.RelayAddr())

	// Register under hostname:port key
	t.connsMu.Lock()
	t.conns[target] = append(t.conns[target], conn)
	t.allConns = append(t.allConns, conn)

	// Also register under resolved IP:port keys so readLoop can match
	// SOCKS5 responses that come back with the server's actual IP.
	if ip := net.ParseIP(host); ip == nil {
		// host is a hostname, resolve it using context
		resolver := &net.Resolver{}
		if ips, err := resolver.LookupIPAddr(ctx, host); err == nil {
			for _, resolved := range ips {
				ipKey := fmt.Sprintf("%s:%s", resolved.IP.String(), portStr)
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

	t.logInfo("tunnel closing", "proxy", t.proxyAddr, "active_conns", len(t.allConns))
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
	if udp := t.remoteUDP.Load(); udp != nil {
		udp.Close()
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
	// Pre-allocate key buffer to avoid fmt.Sprintf per packet
	keyBuf := make([]byte, 0, 64)

	udp := t.remoteUDP.Load()
	if udp == nil {
		return
	}

	for {
		select {
		case <-t.closeCh:
			return
		default:
		}

		udp.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := udp.Read(buf)
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

		// Build source key without fmt.Sprintf allocation
		keyBuf = keyBuf[:0]
		keyBuf = append(keyBuf, sourceHost...)
		keyBuf = append(keyBuf, ':')
		keyBuf = strconv.AppendInt(keyBuf, int64(sourcePort), 10)
		sourceKey := string(keyBuf)

		t.connsMu.RLock()
		conns := t.conns[sourceKey]
		if len(conns) == 0 {
			conns = t.allConns
		}
		if len(conns) == 1 {
			// Single connection — deliver directly without copy
			conns[0].deliverPacket(payload)
		} else {
			for _, c := range conns {
				pktCopy := make([]byte, len(payload))
				copy(pktCopy, payload)
				c.deliverPacket(pktCopy)
			}
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
				t.logInfo("control connection dropped, reconnecting", "proxy", t.proxyAddr)
				t.reconnect()
			} else {
				t.logInfo("control connection dropped, closing", "proxy", t.proxyAddr)
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

	if udp := t.remoteUDP.Load(); udp != nil {
		udp.Close()
	}
	if t.controlTCP != nil {
		t.controlTCP.Close()
	}

	for attempt := 0; attempt < 5; attempt++ {
		if !t.running.Load() {
			return
		}

		t.logInfo("reconnect attempt", "attempt", attempt+1, "proxy", t.proxyAddr)
		if err := t.connect(); err != nil {
			t.logError("reconnect failed", "attempt", attempt+1, "error", err)
			time.Sleep(time.Duration(1<<uint(attempt)) * time.Second)
			continue
		}

		t.logInfo("reconnected successfully", "proxy", t.proxyAddr, "relay", t.relayAddr)
		go t.readLoop()
		go t.monitorControl()
		return
	}

	t.logError("reconnect exhausted all attempts, tunnel shutting down", "proxy", t.proxyAddr)
	t.running.Store(false)
}
