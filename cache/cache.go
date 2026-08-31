package cache

import (
	"container/list"
	"strings"
	"sync"
	"time"

	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/packet"
)

type Key struct {
	Namespace string // optional tenant/profile/cache partition
	Name      string // lower-cased, no trailing dot
	Type      uint16
	Class     uint16
}

func KeyOf(q *packet.DNSQuestion) Key {
	return KeyOfNamespace("", q)
}

// KeyOfNamespace creates an isolated cache key for a tenant, profile, or
// resolver policy. Empty namespace preserves the original single-cache API.
func KeyOfNamespace(namespace string, q *packet.DNSQuestion) Key {
	return Key{
		Namespace: namespace,
		Name:      strings.ToLower(strings.TrimSuffix(q.Name, ".")),
		Type:      uint16(q.Type),
		Class:     uint16(q.Class),
	}
}

type entry struct {
	resp      *packet.DNSPacket
	storedAt  time.Time
	expiresAt time.Time
	element   *list.Element
}

type Cache struct {
	mu     sync.Mutex
	items  map[Key]*entry
	lru    *list.List
	minTTL time.Duration
	maxTTL time.Duration
	negTTL time.Duration
	maxN   int
	now    func() time.Time
}

func New(spec config.CacheSpec) *Cache {
	return &Cache{
		items:  make(map[Key]*entry),
		lru:    list.New(),
		minTTL: spec.MinTTL.Duration(),
		maxTTL: spec.MaxTTL.Duration(),
		negTTL: spec.NegativeTTL.Duration(),
		maxN:   spec.MaxEntries,
		now:    time.Now,
	}
}

func (c *Cache) Get(k Key) (*packet.DNSPacket, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[k]
	if !ok {
		return nil, false
	}
	if !c.now().Before(e.expiresAt) {
		c.remove(k, e)
		return nil, false
	}
	res, err := clonePacket(e.resp)
	if err != nil {
		c.remove(k, e)
		return nil, false
	}
	c.lru.MoveToFront(e.element)
	ageTTLs(res, uint32(c.now().Sub(e.storedAt)/time.Second))
	return res, true
}

func (c *Cache) Put(k Key, resp *packet.DNSPacket) {
	if resp == nil || resp.Header == nil {
		return
	}
	ttl := c.computeTTL(resp)
	if ttl <= 0 {
		return
	}
	stored, err := clonePacket(resp)
	if err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.items[k]; ok {
		c.remove(k, existing)
	}
	if c.maxN > 0 && len(c.items) >= c.maxN {
		c.evictOldest()
	}
	now := c.now()
	e := &entry{resp: stored, storedAt: now, expiresAt: now.Add(ttl)}
	e.element = c.lru.PushFront(k)
	c.items[k] = e
}

func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

func (c *Cache) computeTTL(resp *packet.DNSPacket) time.Duration {
	if resp.Header.RCode == 3 || len(resp.Answers) == 0 {
		return c.negTTL
	}
	min := uint32(0)
	for _, ans := range resp.Answers {
		t := recordTTL(ans)
		if t == 0 {
			continue
		}
		if min == 0 || t < min {
			min = t
		}
	}
	if min == 0 {
		return c.negTTL
	}
	d := time.Duration(min) * time.Second
	if c.minTTL > 0 && d < c.minTTL {
		d = c.minTTL
	}
	if c.maxTTL > 0 && d > c.maxTTL {
		d = c.maxTTL
	}
	return d
}

func (c *Cache) evictOldest() {
	oldest := c.lru.Back()
	if oldest == nil {
		return
	}
	k := oldest.Value.(Key)
	c.remove(k, c.items[k])
}

func (c *Cache) remove(k Key, e *entry) {
	delete(c.items, k)
	if e != nil && e.element != nil {
		c.lru.Remove(e.element)
	}
}

func clonePacket(p *packet.DNSPacket) (*packet.DNSPacket, error) {
	return packet.FromBytes(p.Bytes())
}

func ageTTLs(p *packet.DNSPacket, elapsed uint32) {
	if elapsed == 0 {
		return
	}
	for _, records := range [][]packet.DNSResource{p.Answers, p.Authorities, p.Additionals} {
		for _, record := range records {
			ageRecordTTL(record, elapsed)
		}
	}
}

func ageRecordTTL(r packet.DNSResource, elapsed uint32) {
	// OPT uses the TTL field for extended RCODE/version/flags, not caching.
	if r.GetType() == packet.DNSTypeEDNS {
		return
	}
	set := func(ttl *uint32) {
		if elapsed >= *ttl {
			*ttl = 0
		} else {
			*ttl -= elapsed
		}
	}
	switch x := r.(type) {
	case *packet.DNSResourceRecordA:
		set(&x.TTL)
	case *packet.DNSResourceRecordAAAA:
		set(&x.TTL)
	case *packet.DNSResourceRecordCNAME:
		set(&x.TTL)
	case *packet.DNSResourceRecordMX:
		set(&x.TTL)
	case *packet.DNSResourceRecordNS:
		set(&x.TTL)
	case *packet.DNSResourceRecordTXT:
		set(&x.TTL)
	case *packet.DNSResourceRecordPTR:
		set(&x.TTL)
	case *packet.DNSResourceRecordSOA:
		set(&x.TTL)
	case *packet.DNSResourceRecordSRV:
		set(&x.TTL)
	case *packet.DNSResourceRecordCAA:
		set(&x.TTL)
	case *packet.DNSResourceRecordDS:
		set(&x.TTL)
	case *packet.DNSResourceRecordDNSKEY:
		set(&x.TTL)
	case *packet.DNSResourceRecordRRSIG:
		set(&x.TTL)
	case *packet.DNSResourceRecordNSEC:
		set(&x.TTL)
	case *packet.DNSResourceRecordTLSA:
		set(&x.TTL)
	case *packet.DNSResourceRecordSVCB:
		set(&x.TTL)
	case *packet.DNSResourceRecordUnknown:
		set(&x.TTL)
	}
}

func recordTTL(r packet.DNSResource) uint32 {
	switch x := r.(type) {
	case *packet.DNSResourceRecordA:
		return x.TTL
	case *packet.DNSResourceRecordAAAA:
		return x.TTL
	case *packet.DNSResourceRecordCNAME:
		return x.TTL
	case *packet.DNSResourceRecordMX:
		return x.TTL
	case *packet.DNSResourceRecordNS:
		return x.TTL
	case *packet.DNSResourceRecordTXT:
		return x.TTL
	case *packet.DNSResourceRecordPTR:
		return x.TTL
	case *packet.DNSResourceRecordSOA:
		return x.TTL
	case *packet.DNSResourceRecordSRV:
		return x.TTL
	case *packet.DNSResourceRecordCAA:
		return x.TTL
	case *packet.DNSResourceRecordDS:
		return x.TTL
	case *packet.DNSResourceRecordDNSKEY:
		return x.TTL
	case *packet.DNSResourceRecordRRSIG:
		return x.TTL
	case *packet.DNSResourceRecordNSEC:
		return x.TTL
	case *packet.DNSResourceRecordTLSA:
		return x.TTL
	case *packet.DNSResourceRecordSVCB:
		return x.TTL
	case *packet.DNSResourceRecordEDNS:
		return x.TTL
	case *packet.DNSResourceRecordUnknown:
		return x.TTL
	}
	return 0
}
