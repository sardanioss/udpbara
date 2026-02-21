package udpbara

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// socks5Handshake performs SOCKS5 auth negotiation over a TCP connection.
func socks5Handshake(conn net.Conn, user, pass string) error {
	if user != "" {
		// Offer no-auth (0x00) and username/password (0x02)
		if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
			return err
		}
	} else {
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			return err
		}
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("read auth method: %w", err)
	}
	if resp[0] != 0x05 {
		return errors.New("not a SOCKS5 proxy")
	}

	switch resp[1] {
	case 0x00:
		return nil
	case 0x02:
		return socks5UsernameAuth(conn, user, pass)
	case 0xFF:
		return errors.New("no acceptable auth method")
	default:
		return fmt.Errorf("unsupported auth method: 0x%02x", resp[1])
	}
}

// socks5UsernameAuth performs RFC 1929 username/password authentication.
func socks5UsernameAuth(conn net.Conn, user, pass string) error {
	ulen := len(user)
	plen := len(pass)
	if ulen > 255 {
		return fmt.Errorf("username too long (%d bytes, max 255)", ulen)
	}
	if plen > 255 {
		return fmt.Errorf("password too long (%d bytes, max 255)", plen)
	}
	buf := make([]byte, 0, 3+ulen+plen)
	buf = append(buf, 0x01, byte(ulen))
	buf = append(buf, []byte(user)...)
	buf = append(buf, byte(plen))
	buf = append(buf, []byte(pass)...)

	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("send auth: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}
	if resp[0] != 0x01 {
		return fmt.Errorf("invalid auth subnegotiation version: 0x%02x", resp[0])
	}
	if resp[1] != 0x00 {
		return errors.New("authentication failed")
	}
	return nil
}

// socks5UDPAssociate sends the UDP ASSOCIATE command and returns the relay address.
func socks5UDPAssociate(conn net.Conn) (*net.UDPAddr, error) {
	// VER=5, CMD=3 (UDP ASSOCIATE), RSV=0, ATYP=1 (IPv4), DST.ADDR=0.0.0.0, DST.PORT=0
	req := []byte{
		0x05, 0x03, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("send UDP ASSOCIATE: %w", err)
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("read UDP ASSOCIATE response: %w", err)
	}
	if header[0] != 0x05 {
		return nil, fmt.Errorf("invalid SOCKS5 version in response: 0x%02x", header[0])
	}
	if header[2] != 0x00 {
		return nil, fmt.Errorf("non-zero RSV byte in response: 0x%02x", header[2])
	}
	if header[1] != 0x00 {
		return nil, fmt.Errorf("UDP ASSOCIATE rejected: reply=0x%02x", header[1])
	}

	var bindIP net.IP
	switch header[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, err
		}
		bindIP = net.IP(addr)
	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, err
		}
		bindIP = net.IP(addr)
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, err
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, err
		}
		ips, err := net.LookupIP(string(domain))
		if err != nil {
			return nil, fmt.Errorf("resolve relay domain %s: %w", domain, err)
		}
		bindIP = ips[0]
	default:
		return nil, fmt.Errorf("unsupported ATYP: 0x%02x", header[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, err
	}
	bindPort := binary.BigEndian.Uint16(portBuf)

	// If proxy returned 0.0.0.0, use the proxy's TCP IP
	if bindIP.Equal(net.IPv4zero) || bindIP.IsUnspecified() {
		tcpAddr := conn.RemoteAddr().(*net.TCPAddr)
		bindIP = tcpAddr.IP
	}

	return &net.UDPAddr{IP: bindIP, Port: int(bindPort)}, nil
}

// buildSOCKS5UDPHeader constructs the SOCKS5 UDP request header (no payload).
// ATYP=0x03 (hostname) is used to preserve the hostname for proxy auth.
// Callers must ensure targetHost does not exceed 255 bytes.
func buildSOCKS5UDPHeader(targetHost string, targetPort int) []byte {
	var hdr []byte
	hdr = append(hdr, 0x00, 0x00) // RSV
	hdr = append(hdr, 0x00)       // FRAG = 0

	ip := net.ParseIP(targetHost)
	if ip != nil && ip.To4() != nil {
		hdr = append(hdr, 0x01)
		hdr = append(hdr, ip.To4()...)
	} else if ip != nil {
		hdr = append(hdr, 0x04)
		hdr = append(hdr, ip.To16()...)
	} else {
		// Hostname — preserves hostname for proxy auth
		hdr = append(hdr, 0x03)
		hdr = append(hdr, byte(len(targetHost)))
		hdr = append(hdr, []byte(targetHost)...)
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(targetPort))
	hdr = append(hdr, portBytes...)

	return hdr
}

// parseSOCKS5UDPPacket extracts payload and source address from a SOCKS5 UDP response.
func parseSOCKS5UDPPacket(data []byte) (payload []byte, sourceHost string, sourcePort int, err error) {
	if len(data) < 7 {
		return nil, "", 0, errors.New("packet too short")
	}

	// data[2] is FRAG: non-zero means this is a fragment requiring reassembly.
	// We do not implement UDP fragmentation reassembly; drop such packets.
	if data[2] != 0x00 {
		return nil, "", 0, fmt.Errorf("fragmented SOCKS5 UDP packet (FRAG=0x%02x) not supported", data[2])
	}

	offset := 3 // skip RSV(2) + FRAG(1)
	atyp := data[offset]
	offset++

	switch atyp {
	case 0x01:
		if len(data) < offset+4+2 {
			return nil, "", 0, errors.New("too short for IPv4")
		}
		sourceHost = net.IP(data[offset : offset+4]).String()
		offset += 4
	case 0x04:
		if len(data) < offset+16+2 {
			return nil, "", 0, errors.New("too short for IPv6")
		}
		ip := net.IP(data[offset : offset+16])
		// Normalize IPv4-mapped IPv6 (::ffff:1.2.3.4) to plain IPv4 so dispatch
		// keys match those registered under ATYP=0x01 or resolved IPv4 addresses.
		if v4 := ip.To4(); v4 != nil {
			sourceHost = v4.String()
		} else {
			sourceHost = ip.String()
		}
		offset += 16
	case 0x03:
		dlen := int(data[offset])
		offset++
		if len(data) < offset+dlen+2 {
			return nil, "", 0, errors.New("too short for domain")
		}
		sourceHost = string(data[offset : offset+dlen])
		offset += dlen
	default:
		return nil, "", 0, fmt.Errorf("unsupported ATYP: 0x%02x", atyp)
	}

	sourcePort = int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	return data[offset:], sourceHost, sourcePort, nil
}
