package pipeline

import (
	"strings"

	"github.com/lsongdev/dns-go/cache"
	"github.com/lsongdev/dns-go/filter"
	"github.com/lsongdev/dns-go/packet"
)

// CacheResolver returns a cached response if one exists, else passes through.
// Sits at chain[0] as a fast path; cache writes are the dispatcher's job
// (see Handler.resolve).
type CacheResolver struct {
	cache *cache.Cache
}

func (r *CacheResolver) Query(req *packet.DNSPacket) (*packet.DNSPacket, error) {
	if r.cache == nil || len(req.Questions) == 0 {
		return nil, nil
	}
	resp, ok := r.cache.Get(cache.KeyOf(req.Questions[0]))
	if !ok {
		return nil, nil
	}
	return resp, nil
}

// LocalResolver answers from zones the server is authoritative for. Returns
// (nil, nil) (passes through) for any name outside the configured zones.
type LocalResolver struct {
	local LocalSource
}

func (r *LocalResolver) Query(req *packet.DNSPacket) (*packet.DNSPacket, error) {
	if r.local == nil || len(req.Questions) == 0 {
		return nil, nil
	}
	q := req.Questions[0]
	result := r.local.Resolve(q.Name, q.Type)
	if !result.InZone {
		return nil, nil
	}
	return buildLocalResultResponse(req, result), nil
}

// FilterResolver short-circuits matched names with a synthesized block answer
// (A→0.0.0.0, AAAA→::, others→NXDOMAIN). Pass-through means "not in any
// block/allow rule" — the chain continues.
type FilterResolver struct {
	filter *filter.Filter
}

func (r *FilterResolver) Query(req *packet.DNSPacket) (*packet.DNSPacket, error) {
	if r.filter == nil || len(req.Questions) == 0 {
		return nil, nil
	}
	qname := strings.ToLower(strings.TrimSuffix(req.Questions[0].Name, "."))
	if r.filter.Decide(qname) != filter.Block {
		return nil, nil
	}
	return SynthBlock(req), nil
}
