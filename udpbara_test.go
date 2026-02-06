package udpbara

import (
	"testing"
)

func TestParseProxyURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantAddr  string
		wantUser  string
		wantPass  string
		wantError bool
	}{
		{
			name:     "socks5h with auth",
			url:      "socks5h://user:pass@proxy.example.com:10000",
			wantAddr: "proxy.example.com:10000",
			wantUser: "user",
			wantPass: "pass",
		},
		{
			name:     "socks5 with auth",
			url:      "socks5://user:pass@proxy.example.com:10000",
			wantAddr: "proxy.example.com:10000",
			wantUser: "user",
			wantPass: "pass",
		},
		{
			name:     "no auth",
			url:      "socks5://proxy.example.com:1080",
			wantAddr: "proxy.example.com:1080",
			wantUser: "",
			wantPass: "",
		},
		{
			name:     "username only",
			url:      "socks5://user@proxy.example.com:1080",
			wantAddr: "proxy.example.com:1080",
			wantUser: "user",
			wantPass: "",
		},
		{
			name:     "special chars in password",
			url:      "socks5h://user:p%40ss%2Bword@proxy.example.com:10000",
			wantAddr: "proxy.example.com:10000",
			wantUser: "user",
			wantPass: "p@ss+word",
		},
		{
			name:     "ipv4 host",
			url:      "socks5://user:pass@192.168.1.1:1080",
			wantAddr: "192.168.1.1:1080",
			wantUser: "user",
			wantPass: "pass",
		},
		{
			name:     "ipv6 host",
			url:      "socks5://user:pass@[::1]:1080",
			wantAddr: "[::1]:1080",
			wantUser: "user",
			wantPass: "pass",
		},
		{
			name:      "unsupported scheme",
			url:       "http://proxy.example.com:1080",
			wantError: true,
		},
		{
			name:      "missing host",
			url:       "socks5://",
			wantError: true,
		},
		{
			name:      "empty string",
			url:       "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, user, pass, err := ParseProxyURL(tt.url)
			if tt.wantError {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if addr != tt.wantAddr {
				t.Errorf("addr = %q, want %q", addr, tt.wantAddr)
			}
			if user != tt.wantUser {
				t.Errorf("user = %q, want %q", user, tt.wantUser)
			}
			if pass != tt.wantPass {
				t.Errorf("pass = %q, want %q", pass, tt.wantPass)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ReadBufferSize != 7*1024*1024 {
		t.Errorf("ReadBufferSize = %d, want %d", cfg.ReadBufferSize, 7*1024*1024)
	}
	if cfg.WriteBufferSize != 7*1024*1024 {
		t.Errorf("WriteBufferSize = %d, want %d", cfg.WriteBufferSize, 7*1024*1024)
	}
	if !cfg.TCPKeepAlive {
		t.Error("TCPKeepAlive should be true by default")
	}
	if cfg.TCPKeepAlivePeriod != 30 {
		t.Errorf("TCPKeepAlivePeriod = %d, want 30", cfg.TCPKeepAlivePeriod)
	}
	if cfg.ConnectTimeout != 10 {
		t.Errorf("ConnectTimeout = %d, want 10", cfg.ConnectTimeout)
	}
	if !cfg.AutoReconnect {
		t.Error("AutoReconnect should be true by default")
	}
}
