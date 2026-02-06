package udpbara

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestBuildSOCKS5UDPHeader_Hostname(t *testing.T) {
	hdr := buildSOCKS5UDPHeader("example.com", 443)

	// RSV(2) + FRAG(1) + ATYP(1) + LEN(1) + hostname + PORT(2)
	expectedLen := 3 + 1 + 1 + len("example.com") + 2
	if len(hdr) != expectedLen {
		t.Fatalf("header length = %d, want %d", len(hdr), expectedLen)
	}

	// Check RSV and FRAG
	if hdr[0] != 0x00 || hdr[1] != 0x00 || hdr[2] != 0x00 {
		t.Errorf("RSV/FRAG = %x %x %x, want 00 00 00", hdr[0], hdr[1], hdr[2])
	}

	// ATYP should be 0x03 (hostname)
	if hdr[3] != 0x03 {
		t.Errorf("ATYP = 0x%02x, want 0x03", hdr[3])
	}

	// Hostname length
	if hdr[4] != byte(len("example.com")) {
		t.Errorf("hostname len = %d, want %d", hdr[4], len("example.com"))
	}

	// Hostname
	hostname := string(hdr[5 : 5+len("example.com")])
	if hostname != "example.com" {
		t.Errorf("hostname = %q, want %q", hostname, "example.com")
	}

	// Port (big-endian)
	port := binary.BigEndian.Uint16(hdr[len(hdr)-2:])
	if port != 443 {
		t.Errorf("port = %d, want 443", port)
	}
}

func TestBuildSOCKS5UDPHeader_IPv4(t *testing.T) {
	hdr := buildSOCKS5UDPHeader("192.168.1.1", 8080)

	// RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + PORT(2) = 10
	if len(hdr) != 10 {
		t.Fatalf("header length = %d, want 10", len(hdr))
	}

	// ATYP should be 0x01 (IPv4)
	if hdr[3] != 0x01 {
		t.Errorf("ATYP = 0x%02x, want 0x01", hdr[3])
	}

	ip := net.IP(hdr[4:8])
	if !ip.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("IP = %s, want 192.168.1.1", ip)
	}

	port := binary.BigEndian.Uint16(hdr[8:10])
	if port != 8080 {
		t.Errorf("port = %d, want 8080", port)
	}
}

func TestBuildSOCKS5UDPHeader_IPv6(t *testing.T) {
	hdr := buildSOCKS5UDPHeader("::1", 443)

	// RSV(2) + FRAG(1) + ATYP(1) + IPv6(16) + PORT(2) = 22
	if len(hdr) != 22 {
		t.Fatalf("header length = %d, want 22", len(hdr))
	}

	// ATYP should be 0x04 (IPv6)
	if hdr[3] != 0x04 {
		t.Errorf("ATYP = 0x%02x, want 0x04", hdr[3])
	}

	ip := net.IP(hdr[4:20])
	if !ip.Equal(net.ParseIP("::1")) {
		t.Errorf("IP = %s, want ::1", ip)
	}

	port := binary.BigEndian.Uint16(hdr[20:22])
	if port != 443 {
		t.Errorf("port = %d, want 443", port)
	}
}

func TestParseSOCKS5UDPPacket_IPv4(t *testing.T) {
	// Build a packet: RSV(2) + FRAG(1) + ATYP=0x01 + IPv4(4) + PORT(2) + payload
	pkt := []byte{
		0x00, 0x00, // RSV
		0x00,       // FRAG
		0x01,       // ATYP = IPv4
		93, 184, 216, 34, // 93.184.216.34
		0x01, 0xBB, // port 443
	}
	payload := []byte("hello world")
	pkt = append(pkt, payload...)

	gotPayload, host, port, err := parseSOCKS5UDPPacket(pkt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "93.184.216.34" {
		t.Errorf("host = %q, want %q", host, "93.184.216.34")
	}
	if port != 443 {
		t.Errorf("port = %d, want 443", port)
	}
	if string(gotPayload) != "hello world" {
		t.Errorf("payload = %q, want %q", string(gotPayload), "hello world")
	}
}

func TestParseSOCKS5UDPPacket_IPv6(t *testing.T) {
	pkt := []byte{
		0x00, 0x00, // RSV
		0x00,       // FRAG
		0x04,       // ATYP = IPv6
	}
	pkt = append(pkt, net.ParseIP("2606:4700::1").To16()...)
	pkt = append(pkt, 0x01, 0xBB) // port 443
	pkt = append(pkt, []byte("test")...)

	gotPayload, host, port, err := parseSOCKS5UDPPacket(pkt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "2606:4700::1" {
		t.Errorf("host = %q, want %q", host, "2606:4700::1")
	}
	if port != 443 {
		t.Errorf("port = %d, want 443", port)
	}
	if string(gotPayload) != "test" {
		t.Errorf("payload = %q, want %q", string(gotPayload), "test")
	}
}

func TestParseSOCKS5UDPPacket_Hostname(t *testing.T) {
	hostname := "example.com"
	pkt := []byte{
		0x00, 0x00, // RSV
		0x00,       // FRAG
		0x03,       // ATYP = Domain
		byte(len(hostname)),
	}
	pkt = append(pkt, []byte(hostname)...)
	pkt = append(pkt, 0x00, 0x50) // port 80
	pkt = append(pkt, []byte("data")...)

	gotPayload, host, port, err := parseSOCKS5UDPPacket(pkt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "example.com" {
		t.Errorf("host = %q, want %q", host, "example.com")
	}
	if port != 80 {
		t.Errorf("port = %d, want 80", port)
	}
	if string(gotPayload) != "data" {
		t.Errorf("payload = %q, want %q", string(gotPayload), "data")
	}
}

func TestParseSOCKS5UDPPacket_TooShort(t *testing.T) {
	_, _, _, err := parseSOCKS5UDPPacket([]byte{0x00, 0x00})
	if err == nil {
		t.Error("expected error for short packet")
	}
}

func TestParseSOCKS5UDPPacket_UnsupportedATYP(t *testing.T) {
	pkt := []byte{
		0x00, 0x00, 0x00, // RSV + FRAG
		0x05,             // invalid ATYP
		0x00, 0x00, 0x00, 0x00, // padding
	}
	_, _, _, err := parseSOCKS5UDPPacket(pkt)
	if err == nil {
		t.Error("expected error for unsupported ATYP")
	}
}

func TestBuildAndParseRoundTrip_Hostname(t *testing.T) {
	// Build a header, append a payload, then parse it back
	hdr := buildSOCKS5UDPHeader("example.com", 443)
	payload := []byte("roundtrip test")
	pkt := append(hdr, payload...)

	gotPayload, host, port, err := parseSOCKS5UDPPacket(pkt)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if host != "example.com" {
		t.Errorf("host = %q, want %q", host, "example.com")
	}
	if port != 443 {
		t.Errorf("port = %d, want 443", port)
	}
	if string(gotPayload) != "roundtrip test" {
		t.Errorf("payload = %q, want %q", string(gotPayload), "roundtrip test")
	}
}

func TestBuildAndParseRoundTrip_IPv4(t *testing.T) {
	hdr := buildSOCKS5UDPHeader("10.0.0.1", 8080)
	payload := []byte("ipv4 roundtrip")
	pkt := append(hdr, payload...)

	gotPayload, host, port, err := parseSOCKS5UDPPacket(pkt)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if host != "10.0.0.1" {
		t.Errorf("host = %q, want %q", host, "10.0.0.1")
	}
	if port != 8080 {
		t.Errorf("port = %d, want 8080", port)
	}
	if string(gotPayload) != "ipv4 roundtrip" {
		t.Errorf("payload = %q, want %q", string(gotPayload), "ipv4 roundtrip")
	}
}

func TestBuildAndParseRoundTrip_IPv6(t *testing.T) {
	hdr := buildSOCKS5UDPHeader("::1", 9090)
	payload := []byte("ipv6 roundtrip")
	pkt := append(hdr, payload...)

	gotPayload, host, port, err := parseSOCKS5UDPPacket(pkt)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if host != "::1" {
		t.Errorf("host = %q, want %q", host, "::1")
	}
	if port != 9090 {
		t.Errorf("port = %d, want 9090", port)
	}
	if string(gotPayload) != "ipv6 roundtrip" {
		t.Errorf("payload = %q, want %q", string(gotPayload), "ipv6 roundtrip")
	}
}
