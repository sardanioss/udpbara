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
	closing  atomic.Bool // set by Close(); prevents ConnectContext from opening after Close()
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
	// Check under lock first — fast path if already connected or already closed.
	t.mu.Lock()
	if t.running.Load() {
		t.mu.Unlock()
		return nil
	}
	if t.closing.Load() {
		t.mu.Unlock()
		return fmt.Errorf("tunnel closed")
	}
	if err := ctx.Err(); err != nil {
		t.mu.Unlock()
		return err
	}
	t.mu.Unlock()

	// Perform all network IO without holding t.mu. TCP dial + SOCKS5 handshake
	// can block for up to ConnectTimeout seconds; Close() and monitorControl()
	// must not be starved for the full duration.
	ctrl, relayAddr, remoteUDP, err := t.doConnect(ctx)
	if err != nil {
		t.logError("connect failed", "proxy", t.proxyAddr, "error", err)
		return err
	}

	// Store results under lock. Re-check running (another ConnectContext beat us)
	// and closing (Close() was called while we were doing IO).
	t.mu.Lock()
	if t.running.Load() || t.closing.Load() {
		t.mu.Unlock()
		ctrl.Close()
		remoteUDP.Close()
		if t.closing.Load() {
			return fmt.Errorf("tunnel closed")
		}
		return nil
	}
	t.controlTCP = ctrl
	t.relayAddr = relayAddr
	t.remoteUDP.Store(remoteUDP)
	t.running.Store(true)
	t.mu.Unlock()

	go t.readLoop()
	go t.monitorControl()
	t.logInfo("tunnel connected", "proxy", t.proxyAddr, "relay", relayAddr)
	return nil
}

// doConnect performs the TCP dial, SOCKS5 handshake, and UDP associate without
// touching any Tunnel fields. The caller is responsible for closing ctrl and
// remoteUDP on error or if the results are discarded.
func (t *Tunnel) doConnect(ctx context.Context) (ctrl net.Conn, relayAddr *net.UDPAddr, remoteUDP *net.UDPConn, err error) {
	timeout := time.Duration(t.config.ConnectTimeout) * time.Second
	dialer := &net.Dialer{Timeout: timeout}
	ctrl, err = dialer.DialContext(ctx, "tcp", t.proxyAddr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("tcp connect: %w", err)
	}

	if t.config.TCPKeepAlive {
		if tc, ok := ctrl.(*net.TCPConn); ok {
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(time.Duration(t.config.TCPKeepAlivePeriod) * time.Second)
		}
	}

	if err = socks5Handshake(ctrl, t.proxyUser, t.proxyPass); err != nil {
		ctrl.Close()
		return nil, nil, nil, fmt.Errorf("socks5 handshake: %w", err)
	}

	relayAddr, err = socks5UDPAssociate(ctrl)
	if err != nil {
		ctrl.Close()
		return nil, nil, nil, fmt.Errorf("udp associate: %w", err)
	}

	remoteUDP, err = net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		ctrl.Close()
		return nil, nil, nil, fmt.Errorf("udp dial: %w", err)
	}

	remoteUDP.SetReadBuffer(t.config.ReadBufferSize)
	remoteUDP.SetWriteBuffer(t.config.WriteBufferSize)

	return ctrl, relayAddr, remoteUDP, nil
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

	// Resolve DNS before creating the conn or acquiring the lock.
	// DNS failure is non-fatal: the conn still works via hostname key
	// and allConns broadcast fallback in readLoop.
	var resolvedKeys []string
	if ip := net.ParseIP(host); ip == nil {
		resolver := &net.Resolver{}
		if ips, err := resolver.LookupIPAddr(ctx, host); err == nil {
			resolvedKeys = make([]string, 0, len(ips))
			for _, resolved := range ips {
				// Normalize IPv4-mapped IPv6 to plain IPv4 so keys match those
				// produced by parseSOCKS5UDPPacket when a proxy responds with ATYP=0x01.
				ip := resolved.IP
				if v4 := ip.To4(); v4 != nil {
					ip = v4
				}
				resolvedKeys = append(resolvedKeys, fmt.Sprintf("%s:%s", ip.String(), portStr))
			}
		}
	}

	conn, err := newTunnelConn(t, target, socks5Header)
	if err != nil {
		t.logError("dial failed", "target", target, "error", err)
		return nil, fmt.Errorf("create conn: %w", err)
	}

	t.logDebug("connection created", "target", target, "app", conn.PacketConn().LocalAddr(), "relay", conn.RelayAddr())

	// Register under hostname:port key, allConns, and resolved IP keys.
	// Critical section is just map writes — no I/O.
	t.connsMu.Lock()
	if !t.running.Load() {
		t.connsMu.Unlock()
		conn.Close()
		return nil, fmt.Errorf("tunnel not connected")
	}
	t.conns[target] = append(t.conns[target], conn)
	t.allConns = append(t.allConns, conn)
	for _, ipKey := range resolvedKeys {
		t.conns[ipKey] = append(t.conns[ipKey], conn)
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
	// Set closing first so ConnectContext() sees it even when running is still false
	// (i.e., when Close() races with an in-progress ConnectContext() IO phase).
	t.closing.Store(true)
	if !t.running.CompareAndSwap(true, false) {
		return nil
	}

	close(t.closeCh)

	// Use allConns to close each connection exactly once (conns map has
	// duplicate entries under hostname and IP keys).
	t.connsMu.Lock()
	t.logInfo("tunnel closing", "proxy", t.proxyAddr, "active_conns", len(t.allConns))
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
				// If remoteUDP was replaced by reconnect(), this readLoop is stale.
				// The new readLoop will handle future packets; exit cleanly.
				if t.remoteUDP.Load() != udp {
					return
				}
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

		t.connsMu.RLock()
		conns := t.conns[string(keyBuf)]
		if len(conns) == 0 {
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
// It owns its own lifetime: after a successful reconnect it loops back
// and picks up the new controlTCP rather than spawning a new goroutine,
// which prevents goroutine duplication and the data race on t.controlTCP.
func (t *Tunnel) monitorControl() {
	buf := make([]byte, 1)
	for {
		select {
		case <-t.closeCh:
			return
		default:
		}

		// Copy controlTCP under lock to avoid a data race with reconnect(),
		// which replaces t.controlTCP while holding t.mu.
		t.mu.Lock()
		ctrl := t.controlTCP
		t.mu.Unlock()

		ctrl.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, err := ctrl.Read(buf)
		if err != nil {
			if isTimeout(err) {
				continue
			}

			if t.config.AutoReconnect && t.running.Load() {
				t.logInfo("control connection dropped, reconnecting", "proxy", t.proxyAddr)
				t.reconnect()
				// Loop back and pick up the new controlTCP installed by reconnect().
				continue
			}
			t.logInfo("control connection dropped, closing", "proxy", t.proxyAddr)
			t.Close()
			return
		}
	}
}

// reconnect re-establishes the SOCKS5 session.
// t.mu is held only around each connect() call (state mutations), never during
// the backoff sleep — this lets Close() and monitorControl acquire t.mu
// immediately rather than blocking for up to 31 seconds.
func (t *Tunnel) reconnect() {
	// Close old connections under lock and nil the fields to prevent double-close
	// if Close() is called after all reconnect attempts fail.
	t.mu.Lock()
	if udp := t.remoteUDP.Load(); udp != nil {
		udp.Close()
		t.remoteUDP.Store(nil)
	}
	if t.controlTCP != nil {
		t.controlTCP.Close()
		t.controlTCP = nil
	}
	t.mu.Unlock()

	for attempt := 0; attempt < 5; attempt++ {
		// Fast check without the lock before each attempt.
		if !t.running.Load() {
			return
		}

		t.logInfo("reconnect attempt", "attempt", attempt+1, "proxy", t.proxyAddr)

		// Double-check running inside the lock before releasing for IO.
		t.mu.Lock()
		if !t.running.Load() {
			t.mu.Unlock()
			return
		}
		t.mu.Unlock()

		// IO outside the lock — TCP dial + SOCKS5 handshake must not hold t.mu.
		ctrl, relayAddr, remoteUDP, err := t.doConnect(context.Background())

		if err == nil {
			// Store results under lock. If Close() raced and set running=false,
			// discard the freshly created resources.
			t.mu.Lock()
			if !t.running.Load() {
				t.mu.Unlock()
				ctrl.Close()
				remoteUDP.Close()
				return
			}
			t.controlTCP = ctrl
			t.relayAddr = relayAddr
			t.remoteUDP.Store(remoteUDP)
			t.mu.Unlock()

			t.logInfo("reconnected successfully", "proxy", t.proxyAddr, "relay", relayAddr)
			go t.readLoop()
			// monitorControl is not re-spawned here — the existing goroutine
			// loops back after reconnect() returns and picks up the new controlTCP.
			return
		}

		t.logError("reconnect failed", "attempt", attempt+1, "error", err)

		// Sleep without holding any lock so Close() can proceed immediately.
		// Select on closeCh so we exit early if the tunnel shuts down mid-sleep.
		select {
		case <-t.closeCh:
			return
		case <-time.After(time.Duration(1<<uint(attempt)) * time.Second):
		}
	}

	t.logError("reconnect exhausted all attempts, tunnel shutting down", "proxy", t.proxyAddr)
	// t.mu is free here — Close() can acquire it without deadlock.
	t.Close()
}
