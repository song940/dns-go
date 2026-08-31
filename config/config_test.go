package config

import (
	"strings"
	"testing"
	"time"
)

func TestParseMinimal(t *testing.T) {
	src := `
listens:
  - type: udp
    addr: ":5353"
proxy:
  upstreams:
    - type: udp
      addr: "1.1.1.1:53"
`
	cfg, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(cfg.Listens) != 1 || cfg.Listens[0].Type != "udp" || cfg.Listens[0].Addr != ":5353" {
		t.Errorf("listens parse mismatch: %+v", cfg.Listens)
	}
	if cfg.Cache.MinTTL.Duration() != 60*time.Second {
		t.Errorf("default MinTTL not applied: got %v", cfg.Cache.MinTTL.Duration())
	}
	if cfg.Cache.MaxTTL.Duration() != 24*time.Hour {
		t.Errorf("default MaxTTL not applied: got %v", cfg.Cache.MaxTTL.Duration())
	}
	if cfg.Proxy.Strategy != "failover" {
		t.Errorf("default Strategy not applied: got %q", cfg.Proxy.Strategy)
	}
	if cfg.Mode != "hybrid" {
		t.Errorf("default Mode not applied: got %q", cfg.Mode)
	}
	if cfg.Proxy.Upstreams[0].Timeout.Duration() != 5*time.Second {
		t.Errorf("default Timeout not applied: got %v", cfg.Proxy.Upstreams[0].Timeout.Duration())
	}
}

func TestParseFull(t *testing.T) {
	src := `
listens:
  - type: doh
    addr: ":8443"
  - type: udp
    addr: ":5353"

cache:
  enabled: true
  min_ttl: 30s
  max_ttl: 1h
  max_entries: 5000

domains:
  - domain: example.com
    records:
      - "@ 3600 IN A 192.168.1.1"
  - domain: test.com
    zone_file: ./zones/test.zone

proxy:
  strategy: failover
  upstreams:
    - type: doh
      addr: "https://doh.pub/dns-query"
      method: post
      timeout: 5s
    - type: udp
      addr: "1.1.1.1:53"
      timeout: 3s

filters:
  blocklists:
    - name: local
      file: /etc/dns-go/blocklist.txt
      enabled: true
  allowlists:
    - name: local-allow
      file: /etc/dns-go/allowlist.txt
      enabled: true
  rules:
    - "||doubleclick.net^"
    - "@@||example.com^"
`
	cfg, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if cfg.Cache.MinTTL.Duration() != 30*time.Second {
		t.Errorf("MinTTL: got %v", cfg.Cache.MinTTL.Duration())
	}
	if len(cfg.Domains) != 2 || cfg.Domains[1].ZoneFile != "./zones/test.zone" {
		t.Errorf("domains parse mismatch: %+v", cfg.Domains)
	}
	if len(cfg.Proxy.Upstreams) != 2 {
		t.Fatalf("upstreams: got %d", len(cfg.Proxy.Upstreams))
	}
	if cfg.Proxy.Upstreams[0].Method != "post" {
		t.Errorf("upstream method: got %q", cfg.Proxy.Upstreams[0].Method)
	}
	if len(cfg.Filters.Rules) != 2 {
		t.Errorf("filter rules: got %d", len(cfg.Filters.Rules))
	}
}

func TestValidateErrors(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		wantErr string
	}{
		{
			name: "unknown mode",
			src: `
mode: recursive-magic
listens:
  - type: udp
    addr: ":5353"
`,
			wantErr: "mode",
		},
		{
			name:    "no listens",
			src:     `proxy: {upstreams: [{type: udp, addr: "1.1.1.1:53"}]}`,
			wantErr: "at least one listen",
		},
		{
			name: "missing addr",
			src: `
listens:
  - type: udp
proxy:
  upstreams: [{type: udp, addr: "1.1.1.1:53"}]
`,
			wantErr: "addr required",
		},
		{
			name: "unknown listen type",
			src: `
listens:
  - type: gopher
    addr: ":53"
proxy:
  upstreams: [{type: udp, addr: "1.1.1.1:53"}]
`,
			wantErr: "unknown type",
		},
		{
			name: "unknown upstream type",
			src: `
listens:
  - type: udp
    addr: ":5353"
proxy:
  upstreams:
    - type: smoke
      addr: "1.1.1.1:53"
`,
			wantErr: "proxy.upstreams[0]: unknown type",
		},
		{
			name: "tls without cert",
			src: `
listens:
  - type: dot
    addr: ":853"
proxy:
  upstreams: [{type: udp, addr: "1.1.1.1:53"}]
`,
			wantErr: "requires cert_file and key_file",
		},
		{
			name: "blocklist without source",
			src: `
listens:
  - type: udp
    addr: ":5353"
proxy:
  upstreams: [{type: udp, addr: "1.1.1.1:53"}]
filters:
  blocklists:
    - name: bad
      enabled: true
`,
			wantErr: "url or file required",
		},
		{
			name: "unsupported strategy",
			src: `
listens:
  - type: udp
    addr: ":5353"
proxy:
  strategy: parallel
  upstreams: [{type: udp, addr: "1.1.1.1:53"}]
`,
			wantErr: "not supported",
		},
		{
			name: "bad duration",
			src: `
listens:
  - type: udp
    addr: ":5353"
cache:
  min_ttl: not-a-duration
proxy:
  upstreams: [{type: udp, addr: "1.1.1.1:53"}]
`,
			wantErr: "invalid duration",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.src))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestModeIsolation(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantErr string
	}{
		{
			name: "authoritative requires domain",
			src: `mode: authoritative
listens: [{type: udp, addr: ":5353"}]
`,
			wantErr: "requires at least one domain",
		},
		{
			name: "authoritative rejects upstream",
			src: `mode: authoritative
listens: [{type: udp, addr: ":5353"}]
domains: [{domain: example.com}]
proxy: {upstreams: [{type: udp, addr: "1.1.1.1:53"}]}
`,
			wantErr: "cannot configure recursive cache",
		},
		{
			name: "forwarding rejects domains",
			src: `mode: forwarding
listens: [{type: udp, addr: ":5353"}]
domains: [{domain: example.com}]
`,
			wantErr: "cannot configure authoritative domains",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.src))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("got error %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestDohDefaultMethod(t *testing.T) {
	src := `
listens:
  - type: udp
    addr: ":5353"
proxy:
  upstreams:
    - type: doh
      addr: "https://doh.pub/dns-query"
`
	cfg, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if cfg.Proxy.Upstreams[0].Method != "post" {
		t.Errorf("default doh method should be post, got %q", cfg.Proxy.Upstreams[0].Method)
	}
}

func TestLoadRepoConfig(t *testing.T) {
	cfg, err := Load("../config.yaml")
	if err != nil {
		t.Fatalf("load repo config.yaml: %v", err)
	}
	if len(cfg.Listens) == 0 {
		t.Error("expected at least one listen in repo config.yaml")
	}
	if cfg.Proxy.Strategy != "failover" {
		t.Errorf("repo config should set strategy=failover, got %q", cfg.Proxy.Strategy)
	}
}
