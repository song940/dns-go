package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Duration time.Duration

func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("duration must be a string (e.g. \"5s\", \"24h\"): %w", err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

type Config struct {
	Mode    string       `yaml:"mode"`
	Listens []ListenSpec `yaml:"listens"`
	Cache   CacheSpec    `yaml:"cache"`
	Domains []DomainSpec `yaml:"domains"`
	Proxy   ProxySpec    `yaml:"proxy"`
	Filters FiltersSpec  `yaml:"filters"`
}

type ListenSpec struct {
	Type     string `yaml:"type"`
	Addr     string `yaml:"addr"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type CacheSpec struct {
	Enabled     bool     `yaml:"enabled"`
	MinTTL      Duration `yaml:"min_ttl"`
	MaxTTL      Duration `yaml:"max_ttl"`
	NegativeTTL Duration `yaml:"negative_ttl"`
	MaxEntries  int      `yaml:"max_entries"`
}

type DomainSpec struct {
	Domain   string   `yaml:"domain"`
	Records  []string `yaml:"records"`
	ZoneFile string   `yaml:"zone_file"`
}

type ProxySpec struct {
	Strategy  string         `yaml:"strategy"`
	Upstreams []UpstreamSpec `yaml:"upstreams"`
}

type UpstreamSpec struct {
	Type    string   `yaml:"type"`
	Addr    string   `yaml:"addr"`
	Method  string   `yaml:"method"`
	Timeout Duration `yaml:"timeout"`
}

type FiltersSpec struct {
	Blocklists []ListSpec `yaml:"blocklists"`
	Allowlists []ListSpec `yaml:"allowlists"`
	Rules      []string   `yaml:"rules"`
}

type ListSpec struct {
	Name    string   `yaml:"name"`
	URL     string   `yaml:"url"`
	File    string   `yaml:"file"`
	Enabled bool     `yaml:"enabled"`
	Refresh Duration `yaml:"refresh"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	return Parse(data)
}

func Parse(data []byte) (*Config, error) {
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Mode == "" {
		c.Mode = "hybrid"
	}
	if c.Cache.MinTTL == 0 {
		c.Cache.MinTTL = Duration(60 * time.Second)
	}
	if c.Cache.MaxTTL == 0 {
		c.Cache.MaxTTL = Duration(24 * time.Hour)
	}
	if c.Cache.NegativeTTL == 0 {
		c.Cache.NegativeTTL = Duration(60 * time.Second)
	}
	if c.Cache.MaxEntries == 0 {
		c.Cache.MaxEntries = 10000
	}
	if c.Proxy.Strategy == "" {
		c.Proxy.Strategy = "failover"
	}
	for i := range c.Proxy.Upstreams {
		u := &c.Proxy.Upstreams[i]
		if u.Type == "doh" && u.Method == "" {
			u.Method = "post"
		}
		if u.Timeout == 0 {
			u.Timeout = Duration(5 * time.Second)
		}
	}
}

func (c *Config) Validate() error {
	switch c.Mode {
	case "hybrid", "authoritative", "forwarding":
	default:
		return fmt.Errorf("mode %q invalid (want hybrid, authoritative, or forwarding)", c.Mode)
	}
	if len(c.Listens) == 0 {
		return fmt.Errorf("at least one listen required")
	}
	for i, l := range c.Listens {
		if l.Addr == "" {
			return fmt.Errorf("listens[%d]: addr required", i)
		}
		switch l.Type {
		case "udp", "tcp", "tls", "dot", "doh", "http":
		default:
			return fmt.Errorf("listens[%d]: unknown type %q (want udp/tcp/tls/dot/doh/http)", i, l.Type)
		}
		if (l.Type == "tls" || l.Type == "dot") && (l.CertFile == "" || l.KeyFile == "") {
			return fmt.Errorf("listens[%d]: type %q requires cert_file and key_file", i, l.Type)
		}
	}
	if c.Proxy.Strategy != "failover" {
		return fmt.Errorf("proxy.strategy %q not supported (only 'failover' in v1)", c.Proxy.Strategy)
	}
	for i, u := range c.Proxy.Upstreams {
		switch u.Type {
		case "udp", "tcp", "dot", "doh":
		default:
			return fmt.Errorf("proxy.upstreams[%d]: unknown type %q (want udp/tcp/dot/doh)", i, u.Type)
		}
		if u.Addr == "" {
			return fmt.Errorf("proxy.upstreams[%d]: addr required", i)
		}
		if u.Type == "doh" && u.Method != "get" && u.Method != "post" {
			return fmt.Errorf("proxy.upstreams[%d]: method %q invalid (want get or post)", i, u.Method)
		}
	}
	for i, l := range c.Filters.Blocklists {
		if l.URL == "" && l.File == "" {
			return fmt.Errorf("filters.blocklists[%d]: url or file required", i)
		}
	}
	for i, l := range c.Filters.Allowlists {
		if l.URL == "" && l.File == "" {
			return fmt.Errorf("filters.allowlists[%d]: url or file required", i)
		}
	}
	if c.Mode == "authoritative" {
		if len(c.Domains) == 0 {
			return fmt.Errorf("authoritative mode requires at least one domain")
		}
		if c.Cache.Enabled || len(c.Proxy.Upstreams) > 0 || len(c.Filters.Rules) > 0 || len(c.Filters.Blocklists) > 0 || len(c.Filters.Allowlists) > 0 {
			return fmt.Errorf("authoritative mode cannot configure recursive cache, proxy, or filters")
		}
	}
	if c.Mode == "forwarding" && len(c.Domains) > 0 {
		return fmt.Errorf("forwarding mode cannot configure authoritative domains")
	}
	return nil
}
