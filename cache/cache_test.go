package cache

import (
	"testing"
	"time"

	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/packet"
)

func newTestCache(t *testing.T, minTTL, maxTTL, negTTL time.Duration, max int) (*Cache, *fakeClock) {
	t.Helper()
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := New(config.CacheSpec{
		MinTTL:      config.Duration(minTTL),
		MaxTTL:      config.Duration(maxTTL),
		NegativeTTL: config.Duration(negTTL),
		MaxEntries:  max,
	})
	c.now = clock.Now
	return c, clock
}

type fakeClock struct{ t time.Time }

func (f *fakeClock) Now() time.Time          { return f.t }
func (f *fakeClock) Advance(d time.Duration) { f.t = f.t.Add(d) }

func newAResponse(name string, ttl uint32) *packet.DNSPacket {
	p := &packet.DNSPacket{Header: &packet.DNSHeader{}}
	p.Questions = []*packet.DNSQuestion{{Name: name, Type: packet.DNSTypeA, Class: packet.DNSClassIN}}
	p.AddAnswer(&packet.DNSResourceRecordA{
		DNSResourceRecord: packet.DNSResourceRecord{Name: name, Type: packet.DNSTypeA, Class: packet.DNSClassIN, TTL: ttl},
		Address:           "1.2.3.4",
	})
	return p
}

func newNXDOMAIN(name string) *packet.DNSPacket {
	p := &packet.DNSPacket{Header: &packet.DNSHeader{RCode: 3}}
	p.Questions = []*packet.DNSQuestion{{Name: name, Type: packet.DNSTypeA, Class: packet.DNSClassIN}}
	return p
}

func keyForA(name string) Key {
	return KeyOf(&packet.DNSQuestion{Name: name, Type: packet.DNSTypeA, Class: packet.DNSClassIN})
}

func TestCacheHitAndMiss(t *testing.T) {
	c, _ := newTestCache(t, time.Second, time.Hour, time.Minute, 100)
	k := keyForA("example.com")

	if _, ok := c.Get(k); ok {
		t.Fatal("expected miss on empty cache")
	}

	c.Put(k, newAResponse("example.com", 300))
	got, ok := c.Get(k)
	if !ok {
		t.Fatal("expected hit")
	}
	if len(got.Answers) != 1 {
		t.Errorf("expected 1 answer, got %d", len(got.Answers))
	}
}

func TestCacheExpiry(t *testing.T) {
	c, clock := newTestCache(t, time.Second, time.Hour, time.Minute, 100)
	k := keyForA("example.com")
	c.Put(k, newAResponse("example.com", 60))

	clock.Advance(59 * time.Second)
	if _, ok := c.Get(k); !ok {
		t.Errorf("expected hit before expiry")
	}

	clock.Advance(2 * time.Second)
	if _, ok := c.Get(k); ok {
		t.Errorf("expected miss after expiry")
	}
}

func TestCacheTTLClamp(t *testing.T) {
	c, clock := newTestCache(t, 30*time.Second, 5*time.Minute, time.Minute, 100)
	k := keyForA("a.com")

	c.Put(k, newAResponse("a.com", 5)) // below MinTTL
	clock.Advance(20 * time.Second)
	if _, ok := c.Get(k); !ok {
		t.Error("MinTTL clamp not applied: entry expired before MinTTL")
	}

	c.Put(keyForA("b.com"), newAResponse("b.com", 86400)) // way above MaxTTL
	clock.Advance(6 * time.Minute)
	if _, ok := c.Get(keyForA("b.com")); ok {
		t.Error("MaxTTL clamp not applied: entry still alive after MaxTTL")
	}
}

func TestNegativeCache(t *testing.T) {
	c, clock := newTestCache(t, time.Second, time.Hour, 90*time.Second, 100)
	k := keyForA("nx.example.com")
	c.Put(k, newNXDOMAIN("nx.example.com"))

	clock.Advance(60 * time.Second)
	got, ok := c.Get(k)
	if !ok {
		t.Fatal("expected NXDOMAIN cached")
	}
	if got.Header.RCode != 3 {
		t.Errorf("expected RCode=3, got %d", got.Header.RCode)
	}

	clock.Advance(60 * time.Second)
	if _, ok := c.Get(k); ok {
		t.Error("expected NXDOMAIN expired after negTTL")
	}
}

func TestKeyNormalization(t *testing.T) {
	c, _ := newTestCache(t, time.Second, time.Hour, time.Minute, 100)
	c.Put(keyForA("Example.COM"), newAResponse("Example.COM", 300))

	got, ok := c.Get(keyForA("example.com"))
	if !ok {
		t.Fatal("expected case-insensitive cache hit")
	}
	if len(got.Answers) != 1 {
		t.Errorf("expected 1 answer, got %d", len(got.Answers))
	}

	if _, ok := c.Get(keyForA("example.com.")); !ok {
		t.Error("expected trailing-dot-insensitive cache hit")
	}
}

func TestEvictionAtCapacity(t *testing.T) {
	c, _ := newTestCache(t, time.Second, time.Hour, time.Minute, 2)
	c.Put(keyForA("a.com"), newAResponse("a.com", 300))
	c.Put(keyForA("b.com"), newAResponse("b.com", 300))
	c.Put(keyForA("c.com"), newAResponse("c.com", 300))

	if got := c.Len(); got > 2 {
		t.Errorf("expected len <= 2, got %d", got)
	}

	if _, ok := c.Get(keyForA("c.com")); !ok {
		t.Error("most recent insert should be present")
	}
}

func TestHeaderIsolation(t *testing.T) {
	c, _ := newTestCache(t, time.Second, time.Hour, time.Minute, 100)
	k := keyForA("example.com")
	c.Put(k, newAResponse("example.com", 300))

	got1, _ := c.Get(k)
	got1.Header.ID = 0xAAAA

	got2, _ := c.Get(k)
	if got2.Header.ID == 0xAAAA {
		t.Error("cache entry header leaked between Get calls")
	}
}

func TestRecordIsolationAndTTLAging(t *testing.T) {
	c, clock := newTestCache(t, time.Second, time.Hour, time.Minute, 100)
	k := keyForA("example.com")
	c.Put(k, newAResponse("example.com", 300))

	clock.Advance(45 * time.Second)
	got1, ok := c.Get(k)
	if !ok {
		t.Fatal("expected cache hit")
	}
	a1 := got1.Answers[0].(*packet.DNSResourceRecordA)
	if a1.TTL != 255 {
		t.Fatalf("got aged TTL %d, want 255", a1.TTL)
	}
	a1.Address = "203.0.113.9"
	a1.TTL = 1

	got2, ok := c.Get(k)
	if !ok {
		t.Fatal("expected second cache hit")
	}
	a2 := got2.Answers[0].(*packet.DNSResourceRecordA)
	if a2.Address != "1.2.3.4" || a2.TTL != 255 {
		t.Fatalf("cached record was mutated: address=%s TTL=%d", a2.Address, a2.TTL)
	}
}

func TestLRUEviction(t *testing.T) {
	c, _ := newTestCache(t, time.Second, time.Hour, time.Minute, 2)
	a := keyForA("a.com")
	b := keyForA("b.com")
	cKey := keyForA("c.com")
	c.Put(a, newAResponse("a.com", 300))
	c.Put(b, newAResponse("b.com", 300))
	if _, ok := c.Get(a); !ok { // a becomes most recently used
		t.Fatal("expected a.com cache hit")
	}
	c.Put(cKey, newAResponse("c.com", 300))

	if _, ok := c.Get(b); ok {
		t.Fatal("expected least recently used b.com to be evicted")
	}
	if _, ok := c.Get(a); !ok {
		t.Fatal("expected recently used a.com to remain")
	}
}

func TestCacheNamespaceIsolation(t *testing.T) {
	c, _ := newTestCache(t, time.Second, time.Hour, time.Minute, 100)
	q := &packet.DNSQuestion{Name: "example.com", Type: packet.DNSTypeA, Class: packet.DNSClassIN}
	c.Put(KeyOfNamespace("profile-a", q), newAResponse("example.com", 300))

	if _, ok := c.Get(KeyOfNamespace("profile-b", q)); ok {
		t.Fatal("cache entry leaked across namespaces")
	}
	if _, ok := c.Get(KeyOfNamespace("profile-a", q)); !ok {
		t.Fatal("expected hit in original namespace")
	}
}

func TestModernRecordTTLHelpers(t *testing.T) {
	base := func(rtype packet.DNSType) packet.DNSResourceRecord {
		return packet.DNSResourceRecord{Name: "example.com", Type: rtype, Class: packet.DNSClassIN, TTL: 100}
	}
	records := []packet.DNSResource{
		&packet.DNSResourceRecordCAA{DNSResourceRecord: base(packet.DNSTypeCAA)},
		&packet.DNSResourceRecordDS{DNSResourceRecord: base(packet.DNSTypeDS)},
		&packet.DNSResourceRecordDNSKEY{DNSResourceRecord: base(packet.DNSTypeDNSKEY)},
		&packet.DNSResourceRecordRRSIG{DNSResourceRecord: base(packet.DNSTypeRRSIG)},
		&packet.DNSResourceRecordNSEC{DNSResourceRecord: base(packet.DNSTypeNSEC)},
		&packet.DNSResourceRecordTLSA{DNSResourceRecord: base(packet.DNSTypeTLSA)},
		&packet.DNSResourceRecordSVCB{DNSResourceRecord: base(packet.DNSTypeHTTPS)},
	}
	for _, record := range records {
		if got := recordTTL(record); got != 100 {
			t.Fatalf("type %d TTL=%d, want 100", record.GetType(), got)
		}
		ageRecordTTL(record, 40)
		if got := recordTTL(record); got != 60 {
			t.Fatalf("type %d aged TTL=%d, want 60", record.GetType(), got)
		}
	}
}
