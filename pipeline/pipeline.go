package pipeline

import (
	"fmt"
	"log"
	"os"

	"github.com/lsongdev/dns-go/cache"
	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/filter"
	"github.com/lsongdev/dns-go/packet"
	"github.com/lsongdev/dns-go/proxy"
	"github.com/lsongdev/dns-go/server"
)

// Resolver answers a DNS question. (resp, nil) means "I handled it, stop the
// chain"; (nil, nil) means "pass through to the next resolver"; (nil, err)
// is an attempted-but-failed resolution that gets logged and falls through.
// The dispatcher (Handler.resolve) walks the chain in order and synthesizes
// SERVFAIL if no resolver claims the request. Method name `Query` mirrors the
// rest of the codebase (client.UDPClient.Query, proxy.Pool.Query, etc.) so
// proxy.Pool satisfies Resolver directly without a wrapper.
type Resolver interface {
	Query(req *packet.DNSPacket) (*packet.DNSPacket, error)
}

// UpstreamPool is the surface area pipeline needs from a proxy pool: it both
// resolves (Query) and owns connections (Close). proxy.Pool satisfies this;
// tests provide their own stub. Because UpstreamPool ⊇ Resolver, a pool slots
// into the chain directly — no ProxyResolver wrapper needed.
type UpstreamPool interface {
	Resolver
	Close() error
}

// Handler implements server.DNSHandler with a uniform chain of Resolvers.
// Cache is held separately so the dispatcher can write upstream answers back.
// Authoritative and policy-generated answers deliberately bypass it.
type Handler struct {
	chain              []Resolver
	cache              *cache.Cache
	pool               UpstreamPool // tracked so Close() can shut upstreams down
	recursionAvailable bool
	fallbackRCode      uint8
}

func New(cfg *config.Config) (*Handler, error) {
	if cfg == nil {
		return nil, fmt.Errorf("pipeline: nil config")
	}

	local, err := NewLocalIndex(cfg.Domains)
	if err != nil {
		return nil, fmt.Errorf("pipeline: local zones: %w", err)
	}

	flt, err := buildFilter(cfg.Filters)
	if err != nil {
		return nil, fmt.Errorf("pipeline: filters: %w", err)
	}

	var pool UpstreamPool
	if len(cfg.Proxy.Upstreams) > 0 {
		p, err := proxy.NewPool(cfg.Proxy)
		if err != nil {
			return nil, fmt.Errorf("pipeline: proxy: %w", err)
		}
		pool = p
	}

	var cc *cache.Cache
	if cfg.Cache.Enabled {
		cc = cache.New(cfg.Cache)
	}

	return newHandler(cc, local, flt, pool), nil
}

// newHandler assembles a Handler from already-built components. Nil entries
// are simply skipped, which makes test wiring trivial. The pool is added to
// the chain directly because UpstreamPool ⊇ Resolver.
func newHandler(cc *cache.Cache, local LocalSource, flt *filter.Filter, pool UpstreamPool) *Handler {
	chain := make([]Resolver, 0, 4)
	if local != nil {
		chain = append(chain, &LocalResolver{local: local})
	}
	if cc != nil {
		chain = append(chain, &CacheResolver{cache: cc})
	}
	if flt != nil {
		chain = append(chain, &FilterResolver{filter: flt})
	}
	if pool != nil {
		chain = append(chain, pool)
	}
	return &Handler{
		chain:              chain,
		cache:              cc,
		pool:               pool,
		recursionAvailable: pool != nil,
		fallbackRCode:      rcodeServFail,
	}
}

func (h *Handler) Close() error {
	if h.pool != nil {
		return h.pool.Close()
	}
	return nil
}

// HandleQuery is the entry point invoked by every server transport.
// Concurrency is the transport's job (UDP per-packet, TCP per-conn, HTTP
// per-request) so this runs synchronously.
func (h *Handler) HandleQuery(conn *server.PackConn) {
	req := conn.Request
	if req == nil || req.Header == nil || req.Header.QR != packet.DNSQuery {
		return
	}
	var resp *packet.DNSPacket
	switch {
	case req.Header.OpCode != uint8(packet.DNSOpCodeQuery):
		resp = SynthError(req, rcodeNotImplemented)
	case len(req.Questions) != 1:
		resp = SynthError(req, rcodeFormatError)
	default:
		resp = h.resolve(req)
	}
	if h.recursionAvailable {
		resp.Header.RA = 1
	} else {
		resp.Header.RA = 0
	}
	StripEDNSIfNeeded(req, resp)
	if err := conn.WriteResponse(resp); err != nil {
		log.Printf("[%s] write error: %v", conn.RemoteAddr, err)
	}
}

// resolve walks the chain and returns the first claimed response (or a
// configured fallback). The cache write-back lives here because it is a
// cross-cutting concern. Errors are logged and treated as pass-through.
func (h *Handler) resolve(req *packet.DNSPacket) *packet.DNSPacket {
	for i, r := range h.chain {
		resp, err := r.Query(req)
		if err != nil {
			log.Printf("resolver[%d]: %v", i, err)
			continue
		}
		if resp == nil {
			continue
		}
		if h.cache != nil && cacheableResolver(r) {
			h.cache.Put(cache.KeyOf(req.Questions[0]), resp)
		}
		resp.Header.ID = req.Header.ID
		return resp
	}
	return SynthError(req, h.fallbackRCode)
}

func cacheableResolver(r Resolver) bool {
	switch r.(type) {
	case *LocalResolver, *CacheResolver, *FilterResolver:
		return false
	default:
		return true
	}
}

func buildFilter(spec config.FiltersSpec) (*filter.Filter, error) {
	f := filter.New()
	for _, rule := range spec.Rules {
		if err := f.AddRule(rule); err != nil {
			return nil, fmt.Errorf("rule %q: %w", rule, err)
		}
	}
	for _, l := range spec.Blocklists {
		if err := loadList(f, l, "blocklist"); err != nil {
			return nil, err
		}
	}
	for _, l := range spec.Allowlists {
		if err := loadList(f, l, "allowlist"); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func loadList(f *filter.Filter, l config.ListSpec, kind string) error {
	if !l.Enabled {
		return nil
	}
	if l.File == "" {
		log.Printf("filter: %s %q has no file (url-only sources are not supported in v1; skipping)", kind, l.Name)
		return nil
	}
	if _, err := os.Stat(l.File); os.IsNotExist(err) {
		log.Printf("filter: %s %q file %s does not exist; skipping", kind, l.Name, l.File)
		return nil
	}
	if err := f.AddListFile(l.File); err != nil {
		return fmt.Errorf("%s %q: %w", kind, l.Name, err)
	}
	return nil
}
