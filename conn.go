package udpbara

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// tunnelConn implements net.PacketConn for a single target through a tunnel.
// Uses a real local UDP socket pair for full quic-go compatibility (OOB/ECN support).
type tunnelConn struct {
	tunnel       *Tunnel
	target       string
	socks5Header []byte

	// Real UDP socket pair: app ↔ relay
	appConn   *net.UDPConn // app-facing side (returned to caller)
	relayConn *net.UDPConn // relay-facing side (we read/write internally)
	appAddr   *net.UDPAddr // address of appConn

	closeCh chan struct{}
	closed  bool
	closeMu sync.Mutex

	// Per-connection stats
	pktsSent  atomic.Uint64
	pktsRecv  atomic.Uint64
	bytesSent atomic.Uint64
	bytesRecv atomic.Uint64
}

// newTunnelConn creates a tunnelConn with a local UDP socket pair.
func newTunnelConn(tunnel *Tunnel, target string, socks5Header []byte) (*tunnelConn, error) {
	// Create two UDP sockets on localhost
	relayConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, err
	}
	appConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		relayConn.Close()
		return nil, err
	}

	// Use tunnel config for buffer sizes
	relayConn.SetReadBuffer(tunnel.config.ReadBufferSize)
	relayConn.SetWriteBuffer(tunnel.config.WriteBufferSize)
	appConn.SetReadBuffer(tunnel.config.ReadBufferSize)
	appConn.SetWriteBuffer(tunnel.config.WriteBufferSize)

	c := &tunnelConn{
		tunnel:       tunnel,
		target:       target,
		socks5Header: socks5Header,
		appConn:      appConn,
		relayConn:    relayConn,
		appAddr:      appConn.LocalAddr().(*net.UDPAddr),
		closeCh:      make(chan struct{}),
	}

	// Start relay goroutine (proxy→app delivery is push-based via deliverPacket)
	go c.relayAppToProxy()

	return c, nil
}

// relayAppToProxy reads from app, wraps in SOCKS5, sends to proxy.
func (c *tunnelConn) relayAppToProxy() {
	headerLen := len(c.socks5Header)
	// Pre-allocate send buffer: [socks5Header | payload space]
	// Header is pre-copied once; payload is written at offset headerLen each packet.
	sendBuf := make([]byte, headerLen+65535)
	copy(sendBuf, c.socks5Header)
	// Read buffer starts after the header so payload lands in the right spot
	readBuf := sendBuf[headerLen:]

	for {
		select {
		case <-c.closeCh:
			return
		default:
		}

		c.relayConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, err := c.relayConn.ReadFromUDP(readBuf)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			select {
			case <-c.closeCh:
				return
			default:
				continue
			}
		}

		// Lock-free atomic load instead of mutex
		remoteUDP := c.tunnel.remoteUDP.Load()
		if remoteUDP != nil {
			remoteUDP.Write(sendBuf[:headerLen+n])
			c.pktsSent.Add(1)
			c.bytesSent.Add(uint64(n))
			c.tunnel.pktsSent.Add(1)
			c.tunnel.bytesSent.Add(uint64(n))
		}
	}
}

// deliverPacket sends a packet from the proxy to the app-facing socket.
func (c *tunnelConn) deliverPacket(payload []byte) {
	c.relayConn.WriteToUDP(payload, c.appAddr)
	c.pktsRecv.Add(1)
	c.bytesRecv.Add(uint64(len(payload)))
}

// PacketConn returns the app-facing UDPConn that the caller should use.
// This is a real *net.UDPConn, fully compatible with quic-go.
func (c *tunnelConn) PacketConn() *net.UDPConn {
	return c.appConn
}

// RelayAddr returns the address of the relay side (what the app should "dial" to).
func (c *tunnelConn) RelayAddr() *net.UDPAddr {
	return c.relayConn.LocalAddr().(*net.UDPAddr)
}

// Close cleans up both sockets and deregisters from tunnel.
//
// Lock ordering: closeMu is released before acquiring connsMu to prevent
// deadlock with Tunnel.Close() which acquires connsMu → closeMu.
func (c *tunnelConn) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return nil
	}
	c.closed = true
	close(c.closeCh)

	c.appConn.Close()
	c.relayConn.Close()
	c.closeMu.Unlock()

	// Deregister from tunnel (remove from all key entries and allConns).
	// Safe without closeMu: the closed flag prevents re-entry, so this
	// block runs at most once per tunnelConn.
	c.tunnel.connsMu.Lock()
	for key, conns := range c.tunnel.conns {
		for i, tc := range conns {
			if tc == c {
				c.tunnel.conns[key] = append(conns[:i], conns[i+1:]...)
				if len(c.tunnel.conns[key]) == 0 {
					delete(c.tunnel.conns, key)
				}
				break
			}
		}
	}
	for i, tc := range c.tunnel.allConns {
		if tc == c {
			c.tunnel.allConns = append(c.tunnel.allConns[:i], c.tunnel.allConns[i+1:]...)
			break
		}
	}
	c.tunnel.connsMu.Unlock()

	return nil
}

func isTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	return false
}
