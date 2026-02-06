package udpbara

import (
	"net"
	"testing"
	"time"
)

func TestTunnelConnLocalSocketPair(t *testing.T) {
	// Create a minimal tunnel (not connected to a real proxy)
	tunnel := &Tunnel{
		config:  DefaultConfig(),
		conns:   make(map[string][]*tunnelConn),
		closeCh: make(chan struct{}),
	}

	socks5Header := buildSOCKS5UDPHeader("example.com", 443)
	conn, err := newTunnelConn(tunnel, "example.com:443", socks5Header)
	if err != nil {
		t.Fatalf("newTunnelConn: %v", err)
	}
	defer conn.Close()

	// Verify we get real UDP addresses
	appAddr := conn.PacketConn().LocalAddr()
	relayAddr := conn.RelayAddr()

	if appAddr == nil {
		t.Fatal("appConn has nil address")
	}
	if relayAddr == nil {
		t.Fatal("relayAddr is nil")
	}

	// Both should be on localhost
	udpApp := appAddr.(*net.UDPAddr)
	if !udpApp.IP.IsLoopback() {
		t.Errorf("appConn IP = %s, want loopback", udpApp.IP)
	}
	if !relayAddr.IP.IsLoopback() {
		t.Errorf("relayAddr IP = %s, want loopback", relayAddr.IP)
	}

	// Ports should be different
	if udpApp.Port == relayAddr.Port {
		t.Error("appConn and relayAddr should have different ports")
	}
}

func TestTunnelConnDeliverPacket(t *testing.T) {
	tunnel := &Tunnel{
		config:  DefaultConfig(),
		conns:   make(map[string][]*tunnelConn),
		closeCh: make(chan struct{}),
	}

	socks5Header := buildSOCKS5UDPHeader("example.com", 443)
	conn, err := newTunnelConn(tunnel, "example.com:443", socks5Header)
	if err != nil {
		t.Fatalf("newTunnelConn: %v", err)
	}
	defer conn.Close()

	// Deliver a packet via the relay side
	testData := []byte("hello from proxy")
	conn.deliverPacket(testData)

	// Read from the app side
	buf := make([]byte, 1024)
	conn.PacketConn().SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := conn.PacketConn().ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read from app: %v", err)
	}
	if string(buf[:n]) != "hello from proxy" {
		t.Errorf("got %q, want %q", string(buf[:n]), "hello from proxy")
	}
}

func TestTunnelConnCloseIdempotent(t *testing.T) {
	tunnel := &Tunnel{
		config:  DefaultConfig(),
		conns:   make(map[string][]*tunnelConn),
		closeCh: make(chan struct{}),
	}

	socks5Header := buildSOCKS5UDPHeader("example.com", 443)
	conn, err := newTunnelConn(tunnel, "example.com:443", socks5Header)
	if err != nil {
		t.Fatalf("newTunnelConn: %v", err)
	}

	// Register in tunnel like Dial() does
	tunnel.conns["example.com:443"] = append(tunnel.conns["example.com:443"], conn)
	tunnel.allConns = append(tunnel.allConns, conn)

	// Close multiple times — should not panic
	if err := conn.Close(); err != nil {
		t.Errorf("first close: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Errorf("second close: %v", err)
	}

	// Verify deregistered
	tunnel.connsMu.RLock()
	if len(tunnel.conns) != 0 {
		t.Errorf("conns map should be empty, got %d entries", len(tunnel.conns))
	}
	if len(tunnel.allConns) != 0 {
		t.Errorf("allConns should be empty, got %d entries", len(tunnel.allConns))
	}
	tunnel.connsMu.RUnlock()
}

func TestTunnelConnMultipleConnections(t *testing.T) {
	tunnel := &Tunnel{
		config:  DefaultConfig(),
		conns:   make(map[string][]*tunnelConn),
		closeCh: make(chan struct{}),
	}

	// Create multiple connections
	var conns []*tunnelConn
	for i := 0; i < 5; i++ {
		hdr := buildSOCKS5UDPHeader("example.com", 443+i)
		target := net.JoinHostPort("example.com", "443")
		c, err := newTunnelConn(tunnel, target, hdr)
		if err != nil {
			t.Fatalf("conn %d: %v", i, err)
		}
		tunnel.connsMu.Lock()
		tunnel.conns[target] = append(tunnel.conns[target], c)
		tunnel.allConns = append(tunnel.allConns, c)
		tunnel.connsMu.Unlock()
		conns = append(conns, c)
	}

	// All should have unique addresses
	addrs := make(map[string]bool)
	for i, c := range conns {
		addr := c.PacketConn().LocalAddr().String()
		if addrs[addr] {
			t.Errorf("conn %d has duplicate address %s", i, addr)
		}
		addrs[addr] = true
	}

	// Close all
	for _, c := range conns {
		c.Close()
	}

	// Verify all deregistered
	tunnel.connsMu.RLock()
	if len(tunnel.allConns) != 0 {
		t.Errorf("allConns should be empty after closing all, got %d", len(tunnel.allConns))
	}
	tunnel.connsMu.RUnlock()
}
