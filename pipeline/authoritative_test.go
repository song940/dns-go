package pipeline

import (
	"sync"
	"testing"

	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/filter"
	"github.com/lsongdev/dns-go/packet"
)

func authoritativeZone(t *testing.T) *LocalIndex {
	t.Helper()
	local, err := NewLocalIndex([]config.DomainSpec{{
		Domain: "example.com",
		Records: []string{
			"@ 300 IN SOA ns1.example.com. hostmaster.example.com. 1 3600 600 86400 300",
			"@ 300 IN NS ns1.example.com.",
			"ns1 300 IN A 192.0.2.53",
			"www 300 IN A 192.0.2.1",
			"alias 300 IN CNAME www.example.com.",
			"*.wild 300 IN A 192.0.2.2",
			"child 300 IN NS ns.child.example.com.",
			"ns.child 300 IN A 192.0.2.54",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return local
}

func TestAuthoritativeNODATAStopsForwarding(t *testing.T) {
	pool := &stubPool{resp: makeUpstreamA("www.example.com", "203.0.113.1", 300)}
	h := newHandler(nil, authoritativeZone(t), filter.New(), pool)

	resp := dispatch(t, h, makeRequest("www.example.com", packet.DNSTypeAAAA))
	if resp.Header.RCode != rcodeNoError || resp.Header.AA != 1 {
		t.Fatalf("expected authoritative NODATA, rcode=%d AA=%d", resp.Header.RCode, resp.Header.AA)
	}
	if len(resp.Answers) != 0 || len(resp.Authorities) != 1 || resp.Authorities[0].GetType() != packet.DNSTypeSOA {
		t.Fatalf("expected empty answer with SOA authority, answers=%d authorities=%d", len(resp.Answers), len(resp.Authorities))
	}
	if pool.calls != 0 {
		t.Fatalf("authoritative NODATA leaked to upstream, calls=%d", pool.calls)
	}
}

func TestAuthoritativeNXDOMAINStopsForwarding(t *testing.T) {
	pool := &stubPool{resp: makeUpstreamA("missing.example.com", "203.0.113.1", 300)}
	flt := filter.New()
	_ = flt.AddRule("||missing.example.com^")
	h := newHandler(nil, authoritativeZone(t), flt, pool)

	resp := dispatch(t, h, makeRequest("missing.example.com", packet.DNSTypeA))
	if resp.Header.RCode != rcodeNXDOMAIN || resp.Header.AA != 1 {
		t.Fatalf("expected authoritative NXDOMAIN, rcode=%d AA=%d", resp.Header.RCode, resp.Header.AA)
	}
	if len(resp.Authorities) != 1 || resp.Authorities[0].GetType() != packet.DNSTypeSOA {
		t.Fatal("expected SOA in NXDOMAIN authority section")
	}
	if pool.calls != 0 {
		t.Fatalf("authoritative NXDOMAIN leaked to upstream, calls=%d", pool.calls)
	}
}

func TestAuthoritativeCNAMEChain(t *testing.T) {
	h := newHandler(nil, authoritativeZone(t), nil, nil)
	resp := dispatch(t, h, makeRequest("alias.example.com", packet.DNSTypeA))
	if len(resp.Answers) != 2 {
		t.Fatalf("expected CNAME and target A, got %d answers", len(resp.Answers))
	}
	if resp.Answers[0].GetType() != packet.DNSTypeCNAME || resp.Answers[1].GetType() != packet.DNSTypeA {
		t.Fatalf("unexpected CNAME chain types: %v, %v", resp.Answers[0].GetType(), resp.Answers[1].GetType())
	}
}

func TestAuthoritativeWildcard(t *testing.T) {
	h := newHandler(nil, authoritativeZone(t), nil, nil)
	resp := dispatch(t, h, makeRequest("host.wild.example.com", packet.DNSTypeA))
	if len(resp.Answers) != 1 {
		t.Fatalf("expected wildcard answer, got %d", len(resp.Answers))
	}
	a := resp.Answers[0].(*packet.DNSResourceRecordA)
	if a.Name != "host.wild.example.com" || a.Address != "192.0.2.2" {
		t.Fatalf("unexpected wildcard answer: name=%s address=%s", a.Name, a.Address)
	}
}

func TestAuthoritativeDelegationReferralAndGlue(t *testing.T) {
	h := newHandler(nil, authoritativeZone(t), nil, nil)
	resp := dispatch(t, h, makeRequest("host.child.example.com", packet.DNSTypeA))
	if resp.Header.RCode != rcodeNoError || resp.Header.AA != 0 {
		t.Fatalf("expected non-authoritative referral, rcode=%d AA=%d", resp.Header.RCode, resp.Header.AA)
	}
	if len(resp.Authorities) != 1 || resp.Authorities[0].GetType() != packet.DNSTypeNS {
		t.Fatalf("expected delegation NS, authorities=%d", len(resp.Authorities))
	}
	if len(resp.Additionals) != 1 || resp.Additionals[0].GetType() != packet.DNSTypeA {
		t.Fatalf("expected in-bailiwick A glue, additionals=%d", len(resp.Additionals))
	}
}

func TestAuthoritativeDSAtDelegationIsParentSideNODATA(t *testing.T) {
	h := newHandler(nil, authoritativeZone(t), nil, nil)
	resp := dispatch(t, h, makeRequest("child.example.com", packet.DNSTypeDS))
	if resp.Header.RCode != rcodeNoError || resp.Header.AA != 1 || len(resp.Authorities) != 1 {
		t.Fatalf("expected authoritative DS NODATA, rcode=%d AA=%d authorities=%d", resp.Header.RCode, resp.Header.AA, len(resp.Authorities))
	}
}

func TestLocalIndexReplaceIsAtomicForReaders(t *testing.T) {
	local := authoritativeZone(t)
	replacement := []config.DomainSpec{{Domain: "new.example", Records: []string{"@ 60 IN A 192.0.2.10"}}}
	original := []config.DomainSpec{{Domain: "example.com", Records: []string{"@ 60 IN A 192.0.2.20"}}}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				_ = local.Resolve("www.example.com", packet.DNSTypeA)
				_ = local.Resolve("new.example", packet.DNSTypeA)
			}
		}()
	}
	for i := 0; i < 100; i++ {
		if err := local.Replace(replacement); err != nil {
			t.Fatal(err)
		}
		if err := local.Replace(original); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

func TestAuthoritativeEngineRefusesOutOfZoneWithoutRecursion(t *testing.T) {
	engine, err := NewAuthoritativeEngine(authoritativeZone(t))
	if err != nil {
		t.Fatal(err)
	}
	resp := dispatch(t, engine.handler, makeRequest("outside.example", packet.DNSTypeA))
	if resp.Header.RCode != rcodeRefused {
		t.Fatalf("got rcode %d, want REFUSED", resp.Header.RCode)
	}
	if resp.Header.RA != 0 {
		t.Fatal("authoritative-only engine must not advertise recursion")
	}
}

func TestForwardingEngineAdvertisesRecursion(t *testing.T) {
	pool := &stubPool{resp: makeUpstreamA("outside.example", "192.0.2.99", 60)}
	engine := NewForwardingEngine(nil, nil, pool)
	resp := dispatch(t, engine.handler, makeRequest("outside.example", packet.DNSTypeA))
	if resp.Header.RA != 1 || len(resp.Answers) != 1 {
		t.Fatalf("expected recursive forwarding answer, RA=%d answers=%d", resp.Header.RA, len(resp.Answers))
	}
}

func TestLongestMatchingZoneWins(t *testing.T) {
	local, err := NewLocalIndex([]config.DomainSpec{
		{Domain: "example.com", Records: []string{"www.sub 60 IN A 192.0.2.1"}},
		{Domain: "sub.example.com", Records: []string{"www 60 IN A 192.0.2.2"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := local.Resolve("www.sub.example.com", packet.DNSTypeA)
	if len(result.Answers) != 1 {
		t.Fatalf("expected one answer, got %d", len(result.Answers))
	}
	a := result.Answers[0].(*packet.DNSResourceRecordA)
	if a.Address != "192.0.2.2" {
		t.Fatalf("got parent-zone answer %s, want child-zone answer", a.Address)
	}
}

func TestExistingNameSuppressesHigherWildcard(t *testing.T) {
	local, err := NewLocalIndex([]config.DomainSpec{{
		Domain: "example.com",
		Records: []string{
			"* 60 IN A 192.0.2.1",
			"host.branch 60 IN TXT present",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	result := local.Resolve("missing.branch.example.com", packet.DNSTypeA)
	if result.RCode != rcodeNXDOMAIN || len(result.Answers) != 0 {
		t.Fatalf("higher wildcard crossed closest encloser: rcode=%d answers=%d", result.RCode, len(result.Answers))
	}
}

func TestFailedReplaceKeepsLastGoodSnapshot(t *testing.T) {
	local := authoritativeZone(t)
	err := local.Replace([]config.DomainSpec{{
		Domain:  "example.com",
		Records: []string{"alias IN CNAME one.example.com.", "alias IN A 192.0.2.1"},
	}})
	if err == nil {
		t.Fatal("expected invalid CNAME combination to be rejected")
	}
	result := local.Resolve("www.example.com", packet.DNSTypeA)
	if len(result.Answers) != 1 {
		t.Fatal("failed replace discarded last-known-good snapshot")
	}
}

func TestZoneCompilationRejectsInvalidAuthorityData(t *testing.T) {
	tests := []struct {
		name    string
		records []string
	}{
		{"CNAME conflict", []string{"alias IN CNAME target.example.com.", "alias IN A 192.0.2.1"}},
		{"multiple CNAME", []string{"alias IN CNAME one.example.com.", "alias IN CNAME two.example.com."}},
		{"apex CNAME", []string{"@ IN CNAME target.example.net."}},
		{"CNAME cycle", []string{"one IN CNAME two.example.com.", "two IN CNAME one.example.com."}},
		{"SOA below apex", []string{"child IN SOA ns.example.com. hostmaster.example.com. 1 2 3 4 5"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewLocalIndex([]config.DomainSpec{{Domain: "example.com", Records: tt.records}}); err == nil {
				t.Fatal("expected invalid zone data to be rejected")
			}
		})
	}
}

func TestStorageNeutralZoneSnapshotAPI(t *testing.T) {
	record := &packet.DNSResourceRecordA{
		DNSResourceRecord: packet.DNSResourceRecord{Name: "api.example", Type: packet.DNSTypeA, Class: packet.DNSClassIN, TTL: 60},
		Address:           "192.0.2.80",
	}
	target := &packet.DNSResourceRecordA{
		DNSResourceRecord: packet.DNSResourceRecord{Name: "target.api.example", Type: packet.DNSTypeA, Class: packet.DNSClassIN, TTL: 60},
		Address:           "192.0.2.81",
	}
	alias := &packet.DNSResourceRecordCNAME{
		DNSResourceRecord: packet.DNSResourceRecord{Name: "alias.api.example", Type: packet.DNSTypeCNAME, Class: packet.DNSClassIN, TTL: 60},
		Domain:            "target.api.example",
	}
	local, err := NewLocalIndexFromZones([]ZoneData{{Origin: "api.example", Records: []packet.DNSResource{record, target, alias}}})
	if err != nil {
		t.Fatal(err)
	}
	result := local.Resolve("api.example", packet.DNSTypeA)
	if !result.InZone || len(result.Answers) != 1 {
		t.Fatalf("storage-neutral snapshot lookup failed: inZone=%v answers=%d", result.InZone, len(result.Answers))
	}
	result = local.Resolve("alias.api.example", packet.DNSTypeA)
	if len(result.Answers) != 2 || result.Answers[1].GetType() != packet.DNSTypeA {
		t.Fatalf("canonical FQDN CNAME target was not followed, answers=%d", len(result.Answers))
	}
}

func TestAuthoritativeEngineRequiresApexSOAAndNS(t *testing.T) {
	local, err := NewLocalIndex([]config.DomainSpec{{Domain: "example.com", Records: []string{"@ IN A 192.0.2.1"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAuthoritativeEngine(local); err == nil {
		t.Fatal("expected authoritative engine to reject zone without SOA and NS")
	}
}

func TestAuthoritativeIndexServesModernRecordTypes(t *testing.T) {
	local, err := NewLocalIndex([]config.DomainSpec{{
		Domain: "example.com",
		Records: []string{
			"@ 300 IN CAA 0 issue ca.example",
			"@ 300 IN DNSKEY 257 3 13 AQIDBA==",
			"@ 300 IN HTTPS 1 svc.example.com. alpn=h2",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, rtype := range []packet.DNSType{packet.DNSTypeCAA, packet.DNSTypeDNSKEY, packet.DNSTypeHTTPS} {
		result := local.Resolve("example.com", rtype)
		if len(result.Answers) != 1 || result.Answers[0].GetType() != rtype {
			t.Fatalf("type %d was not indexed: %#v", rtype, result.Answers)
		}
	}
}
