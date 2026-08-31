package pipeline

import (
	"fmt"

	"github.com/lsongdev/dns-go/cache"
	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/filter"
	"github.com/lsongdev/dns-go/proxy"
	"github.com/lsongdev/dns-go/server"
)

// AuthoritativeEngine is a DNSHandler that only serves authoritative zones.
// It never consults a recursive cache, filter policy, or upstream resolver.
type AuthoritativeEngine struct {
	handler *Handler
}

func NewAuthoritativeEngine(source LocalSource) (*AuthoritativeEngine, error) {
	if source == nil {
		return nil, fmt.Errorf("pipeline: authoritative source is required")
	}
	if validator, ok := source.(interface{ ValidateAuthoritative() error }); ok {
		if err := validator.ValidateAuthoritative(); err != nil {
			return nil, fmt.Errorf("pipeline: invalid authoritative source: %w", err)
		}
	}
	handler := newHandler(nil, source, nil, nil)
	handler.fallbackRCode = rcodeRefused
	return &AuthoritativeEngine{handler: handler}, nil
}

func NewAuthoritativeFromConfig(cfg *config.Config) (*AuthoritativeEngine, error) {
	if cfg == nil {
		return nil, fmt.Errorf("pipeline: nil config")
	}
	local, err := NewLocalIndex(cfg.Domains)
	if err != nil {
		return nil, fmt.Errorf("pipeline: local zones: %w", err)
	}
	return NewAuthoritativeEngine(local)
}

func (e *AuthoritativeEngine) HandleQuery(conn *server.PackConn) {
	e.handler.HandleQuery(conn)
}

func (e *AuthoritativeEngine) Close() error { return nil }

// ForwardingEngine is a DNSHandler for recursive forwarding, filtering, and
// caching. It contains no authoritative zones.
type ForwardingEngine struct {
	handler *Handler
}

func NewForwardingEngine(cc *cache.Cache, flt *filter.Filter, pool UpstreamPool) *ForwardingEngine {
	return &ForwardingEngine{handler: newHandler(cc, nil, flt, pool)}
}

func NewForwardingFromConfig(cfg *config.Config) (*ForwardingEngine, error) {
	if cfg == nil {
		return nil, fmt.Errorf("pipeline: nil config")
	}
	flt, err := buildFilter(cfg.Filters)
	if err != nil {
		return nil, fmt.Errorf("pipeline: filters: %w", err)
	}
	var pool UpstreamPool
	if len(cfg.Proxy.Upstreams) > 0 {
		built, err := proxy.NewPool(cfg.Proxy)
		if err != nil {
			return nil, fmt.Errorf("pipeline: proxy: %w", err)
		}
		pool = built
	}
	var cc *cache.Cache
	if cfg.Cache.Enabled {
		cc = cache.New(cfg.Cache)
	}
	return NewForwardingEngine(cc, flt, pool), nil
}

func (e *ForwardingEngine) HandleQuery(conn *server.PackConn) {
	e.handler.HandleQuery(conn)
}

func (e *ForwardingEngine) Close() error { return e.handler.Close() }
