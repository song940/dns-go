package pipeline

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/lsongdev/dns-go/cache"
	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/filter"
	"github.com/lsongdev/dns-go/packet"
	"github.com/lsongdev/dns-go/server"
)

type stubPool struct {
	resp  *packet.DNSPacket
	err   error
	calls int
}

func (s *stubPool) Query(req *packet.DNSPacket) (*packet.DNSPacket, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.resp, nil
}
func (s *stubPool) Close() error { return nil }

func makeRequest(name string, qtype packet.DNSType) *packet.DNSPacket {
	p := &packet.DNSPacket{Header: &packet.DNSHeader{ID: 0x1234}}
	p.AddQuestion(&packet.DNSQuestion{Name: name, Type: qtype, Class: packet.DNSClassIN})
	return p
}

func makeUpstreamA(name, addr string, ttl uint32) *packet.DNSPacket {
	p := &packet.DNSPacket{Header: &packet.DNSHeader{}}
	p.Header.QR = packet.DNSResponse
	p.AddQuestion(&packet.DNSQuestion{Name: name, Type: packet.DNSTypeA, Class: packet.DNSClassIN})
	p.AddAnswer(&packet.DNSResourceRecordA{
		DNSResourceRecord: packet.DNSResourceRecord{Name: name, Type: packet.DNSTypeA, Class: packet.DNSClassIN, TTL: ttl},
		Address:           addr,
	})
	return p
}

func newCache(t *testing.T) *cache.Cache {
	t.Helper()
	return cache.New(config.CacheSpec{
		Enabled:     true,
		MinTTL:      config.Duration(60 * time.Second),
		MaxTTL:      config.Duration(time.Hour),
		NegativeTTL: config.Duration(60 * time.Second),
		MaxEntries:  100,
	})
}

func emptyLocal() *LocalIndex {
	local, err := NewLocalIndex(nil)
	if err != nil {
		panic(err)
	}
	return local
}

func dispatch(t *testing.T, h *Handler, req *packet.DNSPacket) *packet.DNSPacket {
	t.Helper()
	var buf bytes.Buffer
	conn := &server.PackConn{Writer: &buf, RemoteAddr: "test", Request: req}
	h.HandleQuery(conn)
	if buf.Len() == 0 {
		t.Fatal("no response written")
	}
	resp, err := packet.FromBytes(buf.Bytes())
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

func TestHandlerCacheMissThenHit(t *testing.T) {
	pool := &stubPool{resp: makeUpstreamA("google.com", "1.2.3.4", 300)}
	h := newHandler(newCache(t), emptyLocal(), filter.New(), pool)

	resp1 := dispatch(t, h, makeRequest("google.com", packet.DNSTypeA))
	if pool.calls != 1 {
		t.Errorf("first call should hit upstream, calls=%d", pool.calls)
	}
	if len(resp1.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp1.Answers))
	}

	resp2 := dispatch(t, h, makeRequest("google.com", packet.DNSTypeA))
	if pool.calls != 1 {
		t.Errorf("second call should hit cache, calls=%d", pool.calls)
	}
	if len(resp2.Answers) != 1 {
		t.Fatalf("expected 1 cached answer, got %d", len(resp2.Answers))
	}
	if resp2.Header.ID != 0x1234 {
		t.Errorf("cached response should adopt request ID, got %#x", resp2.Header.ID)
	}
}

func TestHandlerLocalShortCircuits(t *testing.T) {
	pool := &stubPool{resp: makeUpstreamA("nas.example.com", "9.9.9.9", 300)}
	local, err := NewLocalIndex([]config.DomainSpec{
		{Domain: "example.com", Records: []string{"nas IN A 192.168.1.10"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := newHandler(nil, local, filter.New(), pool)

	resp := dispatch(t, h, makeRequest("nas.example.com", packet.DNSTypeA))
	if pool.calls != 0 {
		t.Errorf("local hit should not call upstream, calls=%d", pool.calls)
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answers))
	}
	a, ok := resp.Answers[0].(*packet.DNSResourceRecordA)
	if !ok {
		t.Fatalf("expected A record, got %T", resp.Answers[0])
	}
	if a.Address != "192.168.1.10" {
		t.Errorf("expected local 192.168.1.10, got %s", a.Address)
	}
	if resp.Header.AA != 1 {
		t.Errorf("local response should be authoritative")
	}
}

func TestHandlerFilterBlock(t *testing.T) {
	pool := &stubPool{resp: makeUpstreamA("ad.bad.com", "5.5.5.5", 300)}
	flt := filter.New()
	if err := flt.AddRule("||bad.com^"); err != nil {
		t.Fatal(err)
	}
	h := newHandler(nil, emptyLocal(), flt, pool)

	resp := dispatch(t, h, makeRequest("ad.bad.com", packet.DNSTypeA))
	if pool.calls != 0 {
		t.Errorf("blocked query should not reach upstream, calls=%d", pool.calls)
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("expected 1 synthetic answer, got %d", len(resp.Answers))
	}
	a := resp.Answers[0].(*packet.DNSResourceRecordA)
	if a.Address != "0.0.0.0" {
		t.Errorf("expected 0.0.0.0 sinkhole, got %s", a.Address)
	}
}

func TestHandlerFilterBlockIsNotCached(t *testing.T) {
	flt := filter.New()
	if err := flt.AddRule("||bad.com^"); err != nil {
		t.Fatal(err)
	}
	cc := newCache(t)
	h := newHandler(cc, emptyLocal(), flt, nil)
	dispatch(t, h, makeRequest("bad.com", packet.DNSTypeA))
	if got := cc.Len(); got != 0 {
		t.Fatalf("filter result must not enter recursive cache, len=%d", got)
	}
}

func TestHandlerFilterBlockAAAA(t *testing.T) {
	flt := filter.New()
	if err := flt.AddRule("||bad.com^"); err != nil {
		t.Fatal(err)
	}
	h := newHandler(nil, emptyLocal(), flt, nil)

	resp := dispatch(t, h, makeRequest("bad.com", packet.DNSTypeAAAA))
	if len(resp.Answers) != 1 {
		t.Fatalf("expected 1 synthetic answer, got %d", len(resp.Answers))
	}
	aaaa := resp.Answers[0].(*packet.DNSResourceRecordAAAA)
	if aaaa.Address != "::" {
		t.Errorf("expected :: sinkhole, got %s", aaaa.Address)
	}
}

func TestHandlerProxyServfail(t *testing.T) {
	pool := &stubPool{err: errors.New("upstream down")}
	h := newHandler(nil, emptyLocal(), filter.New(), pool)

	resp := dispatch(t, h, makeRequest("google.com", packet.DNSTypeA))
	if resp.Header.RCode != 2 {
		t.Errorf("expected SERVFAIL (rcode=2), got %d", resp.Header.RCode)
	}
}

func TestHandlerNoPoolReturnsServfail(t *testing.T) {
	h := newHandler(nil, emptyLocal(), filter.New(), nil)

	resp := dispatch(t, h, makeRequest("google.com", packet.DNSTypeA))
	if resp.Header.RCode != 2 {
		t.Errorf("expected SERVFAIL with no pool, got rcode=%d", resp.Header.RCode)
	}
}

func TestHandlerRejectsMalformedQuestionCount(t *testing.T) {
	h := newHandler(nil, emptyLocal(), filter.New(), nil)
	req := &packet.DNSPacket{Header: &packet.DNSHeader{ID: 0x1234}}

	resp := dispatch(t, h, req)
	if resp.Header.RCode != rcodeFormatError {
		t.Fatalf("got rcode %d, want FORMERR", resp.Header.RCode)
	}
}

func TestHandlerRejectsUnsupportedOpcode(t *testing.T) {
	h := newHandler(nil, emptyLocal(), filter.New(), nil)
	req := makeRequest("example.com", packet.DNSTypeA)
	req.Header.OpCode = uint8(packet.DNSOpCodeUpdate)

	resp := dispatch(t, h, req)
	if resp.Header.RCode != rcodeNotImplemented {
		t.Fatalf("got rcode %d, want NOTIMP", resp.Header.RCode)
	}
}

func TestStripEDNSWhenRequestHasNone(t *testing.T) {
	upstreamResp := makeUpstreamA("google.com", "1.2.3.4", 300)
	upstreamResp.AddAdditionalEDNS(4096, 0, 0, false)

	pool := &stubPool{resp: upstreamResp}
	h := newHandler(nil, emptyLocal(), filter.New(), pool)

	resp := dispatch(t, h, makeRequest("google.com", packet.DNSTypeA))
	for _, add := range resp.Additionals {
		if add.GetType() == packet.DNSTypeEDNS {
			t.Error("EDNS should be stripped when request has none")
		}
	}
	if resp.Header.ARCount != uint16(len(resp.Additionals)) {
		t.Errorf("ARCount mismatch: header=%d, additionals=%d", resp.Header.ARCount, len(resp.Additionals))
	}
}

func TestStripEDNSPreservedWhenRequestHasIt(t *testing.T) {
	upstreamResp := makeUpstreamA("google.com", "1.2.3.4", 300)
	upstreamResp.AddAdditionalEDNS(4096, 0, 0, false)

	pool := &stubPool{resp: upstreamResp}
	h := newHandler(nil, emptyLocal(), filter.New(), pool)

	req := makeRequest("google.com", packet.DNSTypeA)
	req.AddAdditionalEDNS(4096, 0, 0, false)

	resp := dispatch(t, h, req)
	hasEDNSResp := false
	for _, add := range resp.Additionals {
		if add.GetType() == packet.DNSTypeEDNS {
			hasEDNSResp = true
		}
	}
	if !hasEDNSResp {
		t.Error("EDNS should be preserved when client sent OPT")
	}
}

func TestStripEDNSPaddingFromUpstream(t *testing.T) {
	upstreamResp := makeUpstreamA("google.com", "1.2.3.4", 300)
	upstreamResp.AddAdditionalEDNS(4096, 0, 0, false)
	for _, add := range upstreamResp.Additionals {
		if opt, ok := add.(*packet.DNSResourceRecordEDNS); ok {
			opt.AddEDNSOptionPadding(384)
		}
	}

	pool := &stubPool{resp: upstreamResp}
	h := newHandler(nil, emptyLocal(), filter.New(), pool)

	req := makeRequest("google.com", packet.DNSTypeA)
	req.AddAdditionalEDNS(4096, 0, 0, false)

	resp := dispatch(t, h, req)
	for _, add := range resp.Additionals {
		opt, ok := add.(*packet.DNSResourceRecordEDNS)
		if !ok {
			continue
		}
		for _, o := range opt.Options {
			if o.Code == packet.EDNSOptionPadding {
				t.Errorf("PAD option should be stripped from forwarded response, got %d bytes", len(o.Data))
			}
		}
	}
}

func TestHandlerLocalIsNotCached(t *testing.T) {
	local, err := NewLocalIndex([]config.DomainSpec{
		{Domain: "example.com", Records: []string{"nas IN A 10.0.0.1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cc := newCache(t)
	h := newHandler(cc, local, filter.New(), nil)

	dispatch(t, h, makeRequest("nas.example.com", packet.DNSTypeA))
	if got := cc.Len(); got != 0 {
		t.Errorf("local hit must not enter recursive cache, len=%d", got)
	}
}

func TestNewFromConfig(t *testing.T) {
	cfg := &config.Config{
		Listens: []config.ListenSpec{{Type: "udp", Addr: ":53"}},
		Cache: config.CacheSpec{
			Enabled:     true,
			MinTTL:      config.Duration(60 * time.Second),
			MaxTTL:      config.Duration(time.Hour),
			NegativeTTL: config.Duration(60 * time.Second),
			MaxEntries:  100,
		},
		Domains: []config.DomainSpec{
			{Domain: "lan", Records: []string{"nas IN A 192.168.1.10"}},
		},
		Proxy: config.ProxySpec{
			Strategy:  "failover",
			Upstreams: []config.UpstreamSpec{{Type: "udp", Addr: "1.1.1.1:53"}},
		},
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if h.cache == nil {
		t.Error("cache should be initialised")
	}
	if h.pool == nil {
		t.Error("pool should be initialised when upstreams configured")
	}
	if len(h.chain) != 4 {
		t.Errorf("expected chain [local, cache, filter, proxy], got len=%d", len(h.chain))
	}
}
