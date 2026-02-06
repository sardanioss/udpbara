<p align="center">
  <img src="assets/logo.png" alt="udpbara" width="200"/>
</p>

<h1 align="center">udpbara</h1>

<p align="center">
  <b>Userspace UDP relay for QUIC/HTTP3 through SOCKS5 proxies</b><br>
  <i>Cuz UDP deserve to chill in tunnel too.</i>
</p>

<p align="center">
  <a href="#why">Why</a> &bull;
  <a href="#how-it-works">How It Works</a> &bull;
  <a href="#install">Install</a> &bull;
  <a href="#usage">Usage</a> &bull;
  <a href="#api">API</a>
</p>

---

## Why

So here's the deal, QUIC and HTTP/3 run over UDP. SOCKS5 proxies technically support UDP through this thing called `UDP ASSOCIATE`. In theory, tunneling QUIC through SOCKS5 should be straightforward. In practice? Literally nobody does this. And honestly, fair enough:

- **quic-go is picky fr**: it doesn't just want any `net.PacketConn`. It needs a real `*net.UDPConn` because it's doing OOB messages, ECN bits, platform-specific socket ops, basically the whole deal. Hand it a fake conn and watch things break in the most confusing ways possible.
- **SOCKS5 UDP ASSOCIATE is unhinged**: it binds some random relay address, wraps every single packet with its own headers, and straight up kills your session if the TCP control connection drops. Most SOCKS5 libraries looked at this part of the spec and said "nah".
- **The hostname-vs-IP nightmare**: residential/ISP proxies auth based on the hostname in your SOCKS5 request. Resolve DNS locally and send raw IPs? Auth fails silently. Send hostnames? Cool, but now the relay responds with IPs and your dispatcher has zero idea which connection those packets belong to.

udpbara deals with all of this. It spins up a real local UDP socket pair per connection and quic-go gets its beloved `*net.UDPConn` with full OOB/ECN support, while udpbara handles the SOCKS5 wrapping and dispatch behind the scenes.

No TUN interfaces. No root. No iptables. No kernel modules. Just pure userspace Go doing its thing.

## How It Works

```
┌─────────────┐         ┌──────────────────────┐         ┌──────────────┐
│   quic-go   │  UDP    │       udpbara        │  UDP    │  SOCKS5      │
│             │◄───────►│                      │◄───────►│  Proxy       │
│  (real UDP  │  local  │  appConn ↔ relayConn │  inet   │  (UDP relay) │
│   socket)   │  pair   │  + SOCKS5 wrapping   │         │              │
└─────────────┘         └──────────────────────┘         └──────────────┘
                              │                                │
                              │ TCP (control)                  │
                              └────────────────────────────────┘
```

1. **TCP Handshake** — udpbara connects to the SOCKS5 proxy over TCP, authenticates (username/password), and sends `UDP ASSOCIATE` to get a relay address.

2. **Local Socket Pair** — For each target, it creates two `*net.UDPConn` sockets on localhost:
   - `appConn` — handed to quic-go (or whatever UDP client you're using)
   - `relayConn` — internal side that wraps/unwraps SOCKS5 UDP headers

3. **Outbound (app → proxy)** — Packets from `appConn` hit `relayConn`, get wrapped with the SOCKS5 UDP header (preserving the hostname for proxy auth), and are sent to the proxy's relay address.

4. **Inbound (proxy → app)** — Packets from the proxy are read on the tunnel's shared UDP socket, stripped of the SOCKS5 header, and dispatched to the correct `relayConn` → `appConn` based on source address. Dual-key lookup (hostname + resolved IPs) with fallback broadcast handles the hostname-vs-IP mismatch.

5. **Lifecycle** — The TCP control connection is monitored. If it drops, udpbara auto-reconnects with exponential backoff (up to 5 attempts).

## Install

```bash
go get github.com/user/udpbara
```

## Usage

### Quick — One-Shot Dial

```go
import "github.com/user/udpbara"

// Creates tunnel + connection in one call
conn, err := udpbara.Dial("socks5h://user:pass@proxy:10000", "target.com:443")
if err != nil {
    log.Fatal(err)
}
defer conn.Close() // cleans up tunnel too

// Use with quic-go
transport := &quic.Transport{
    Conn: conn.PacketConn(), // real *net.UDPConn
}
quicConn, err := transport.Dial(ctx, conn.RelayAddr(), tlsConfig, quicConfig)
```

### Tunnel — Multiple Targets, One Proxy

```go
// Create and connect tunnel
tunnel, err := udpbara.NewTunnel("socks5h://user:pass@proxy:10000")
if err != nil {
    log.Fatal(err)
}
if err := tunnel.Connect(); err != nil {
    log.Fatal(err)
}
defer tunnel.Close()

// Dial multiple targets through the same proxy session
conn1, _ := tunnel.Dial("api.example.com:443")
conn2, _ := tunnel.Dial("cdn.example.com:443")
defer conn1.Close()
defer conn2.Close()

// Each gets its own *net.UDPConn
fmt.Println(conn1.PacketConn().LocalAddr()) // 127.0.0.1:xxxxx
fmt.Println(conn2.PacketConn().LocalAddr()) // 127.0.0.1:yyyyy
```

### Manager — Multiple Proxies

```go
mgr := udpbara.NewManager()

// Add tunnels for different proxies
mgr.AddTunnel("us-east", "socks5h://user:pass@us-east-proxy:10000")
mgr.AddTunnel("eu-west", "socks5h://user:pass@eu-west-proxy:10000")

// Dial through specific tunnels
conn, _ := mgr.Dial("us-east", "", "target.com:443")
defer conn.Close()

// Cleanup
mgr.CloseAll()
```

### With HTTP/3 (quic-go + httpcloak)

```go
// Set up tunnel
tunnel, _ := udpbara.NewTunnel(proxyURL)
tunnel.Connect()
defer tunnel.Close()

conn, _ := tunnel.Dial("example.com:443")
defer conn.Close()

// QUIC transport using udpbara's real UDPConn
quicTransport := &quic.Transport{
    Conn: conn.PacketConn(),
}
defer quicTransport.Close()

// HTTP/3 with custom dial through the relay
relayAddr := conn.RelayAddr()
h3Transport := &http3.Transport{
    TLSClientConfig: tlsConfig,
    QUICConfig:      quicConfig,
    Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
        return quicTransport.DialEarly(ctx, relayAddr, tlsCfg, cfg)
    },
}
defer h3Transport.Close()

resp, err := h3Transport.RoundTrip(req)
```

## API

### Top-Level

| Function | Description |
|----------|-------------|
| `Dial(proxyURL, target, ...Config)` | One-shot: creates tunnel + connection, caller owns both |
| `NewTunnel(proxyURL, ...Config)` | Creates a reusable tunnel (call `Connect()` next) |
| `NewManager(...Config)` | Creates a multi-tunnel manager |

### Tunnel

| Method | Description |
|--------|-------------|
| `Connect()` | Establishes SOCKS5 UDP ASSOCIATE session |
| `Dial(target)` | Creates a new connection to `host:port` through this tunnel |
| `Stats()` | Returns packet/byte counters |
| `Close()` | Shuts down tunnel and all connections |

### Connection

| Method | Description |
|--------|-------------|
| `PacketConn()` | Returns `*net.UDPConn` for quic-go |
| `RelayAddr()` | Returns `*net.UDPAddr` to pass to `quic.Transport.Dial()` |
| `Tunnel()` | Returns the parent `*Tunnel` |
| `Close()` | Closes this connection (and tunnel if created via top-level `Dial`) |

### Config

| Field | Default | Description |
|-------|---------|-------------|
| `ReadBufferSize` | 7 MB | UDP socket read buffer |
| `WriteBufferSize` | 7 MB | UDP socket write buffer |
| `TCPKeepAlive` | `true` | Keepalive on SOCKS5 control connection |
| `TCPKeepAlivePeriod` | 30s | Keepalive probe interval |
| `ConnectTimeout` | 10s | Proxy connection timeout |
| `AutoReconnect` | `true` | Auto-reconnect on control drop |

## License

MIT
