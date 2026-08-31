package zone

import (
	"testing"

	"github.com/lsongdev/dns-go/packet"
)

func TestParseA(t *testing.T) {
	data := []byte("example.com. 3600 IN A 192.168.1.1\n")
	z, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(z.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(z.Records))
	}
	a, ok := z.Records[0].(*packet.DNSResourceRecordA)
	if !ok {
		t.Fatalf("expected A record, got %T", z.Records[0])
	}
	if a.Name != "example.com" {
		t.Errorf("expected name example.com, got %q", a.Name)
	}
	if a.Address != "192.168.1.1" {
		t.Errorf("expected address 192.168.1.1, got %q", a.Address)
	}
	if a.TTL != 3600 {
		t.Errorf("expected TTL 3600, got %d", a.TTL)
	}
	if a.Class != packet.DNSClassIN {
		t.Errorf("expected class IN, got %v", a.Class)
	}
}

func TestParseAAAA(t *testing.T) {
	data := []byte("example.com. 3600 IN AAAA 2001:db8::1\n")
	z, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	aaaa, ok := z.Records[0].(*packet.DNSResourceRecordAAAA)
	if !ok {
		t.Fatalf("expected AAAA record, got %T", z.Records[0])
	}
	if aaaa.Address != "2001:db8::1" {
		t.Errorf("expected address 2001:db8::1, got %q", aaaa.Address)
	}
}

func TestParseCNAME(t *testing.T) {
	data := []byte("www.example.com. 3600 IN CNAME example.com.\n")
	z, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	cname, ok := z.Records[0].(*packet.DNSResourceRecordCNAME)
	if !ok {
		t.Fatalf("expected CNAME record, got %T", z.Records[0])
	}
	if cname.Domain != "example.com." {
		t.Errorf("expected target example.com., got %q", cname.Domain)
	}
}

func TestParseNS(t *testing.T) {
	data := []byte("example.com. 3600 IN NS ns1.example.com.\n")
	z, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	ns, ok := z.Records[0].(*packet.DNSResourceRecordNS)
	if !ok {
		t.Fatalf("expected NS record, got %T", z.Records[0])
	}
	if ns.NameServer != "ns1.example.com." {
		t.Errorf("expected ns1.example.com., got %q", ns.NameServer)
	}
}

func TestParseMX(t *testing.T) {
	data := []byte("example.com. 3600 IN MX 10 mail.example.com.\n")
	z, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	mx, ok := z.Records[0].(*packet.DNSResourceRecordMX)
	if !ok {
		t.Fatalf("expected MX record, got %T", z.Records[0])
	}
	if mx.Preference != 10 {
		t.Errorf("expected preference 10, got %d", mx.Preference)
	}
	if mx.Exchange != "mail.example.com." {
		t.Errorf("expected mail.example.com., got %q", mx.Exchange)
	}
}

func TestParseTXT(t *testing.T) {
	data := []byte("example.com. 3600 IN TXT \"v=spf1 include:_spf.example.com ~all\"\n")
	z, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	txt, ok := z.Records[0].(*packet.DNSResourceRecordTXT)
	if !ok {
		t.Fatalf("expected TXT record, got %T", z.Records[0])
	}
	expected := "v=spf1 include:_spf.example.com ~all"
	if txt.Content != expected {
		t.Errorf("expected %q, got %q", expected, txt.Content)
	}
}

func TestParseSOA(t *testing.T) {
	data := []byte(`example.com. 3600 IN SOA ns1.example.com. admin.example.com. (
	2024010101 ; serial
	3600       ; refresh
	900        ; retry
	86400      ; expire
	600 )      ; minimum
`)
	z, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(z.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(z.Records))
	}
	soa, ok := z.Records[0].(*packet.DNSResourceRecordSOA)
	if !ok {
		t.Fatalf("expected SOA record, got %T", z.Records[0])
	}
	if soa.MName != "ns1.example.com." {
		t.Errorf("expected MName ns1.example.com., got %q", soa.MName)
	}
	if soa.RName != "admin.example.com." {
		t.Errorf("expected RName admin.example.com., got %q", soa.RName)
	}
	if soa.Serial != 2024010101 {
		t.Errorf("expected serial 2024010101, got %d", soa.Serial)
	}
	if soa.Refresh != 3600 {
		t.Errorf("expected refresh 3600, got %d", soa.Refresh)
	}
	if soa.Retry != 900 {
		t.Errorf("expected retry 900, got %d", soa.Retry)
	}
	if soa.Expire != 86400 {
		t.Errorf("expected expire 86400, got %d", soa.Expire)
	}
	if soa.Minimum != 600 {
		t.Errorf("expected minimum 600, got %d", soa.Minimum)
	}
}

func TestParseSRV(t *testing.T) {
	data := []byte("_sip._tcp.example.com. 3600 IN SRV 10 20 5060 sipserver.example.com.\n")
	z, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	srv, ok := z.Records[0].(*packet.DNSResourceRecordSRV)
	if !ok {
		t.Fatalf("expected SRV record, got %T", z.Records[0])
	}
	if srv.Priority != 10 {
		t.Errorf("expected priority 10, got %d", srv.Priority)
	}
	if srv.Weight != 20 {
		t.Errorf("expected weight 20, got %d", srv.Weight)
	}
	if srv.Port != 5060 {
		t.Errorf("expected port 5060, got %d", srv.Port)
	}
	if srv.Target != "sipserver.example.com." {
		t.Errorf("expected sipserver.example.com., got %q", srv.Target)
	}
}

func TestParsePTR(t *testing.T) {
	data := []byte("1.0.168.192.in-addr.arpa. 3600 IN PTR example.com.\n")
	z, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	ptr, ok := z.Records[0].(*packet.DNSResourceRecordPTR)
	if !ok {
		t.Fatalf("expected PTR record, got %T", z.Records[0])
	}
	if ptr.PtrDomainName != "example.com." {
		t.Errorf("expected example.com., got %q", ptr.PtrDomainName)
	}
}

func TestParseMultipleRecords(t *testing.T) {
	data := []byte(
		"example.com. 3600 IN A 192.168.1.1\n" +
			"example.com. 3600 IN AAAA 2001:db8::1\n" +
			"www.example.com. 3600 IN CNAME example.com.\n",
	)
	z, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(z.Records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(z.Records))
	}
}

func TestParseWithOrigin(t *testing.T) {
	data := []byte(
		"$ORIGIN example.com.\n" +
			"@ 3600 IN A 192.168.1.1\n" +
			"www 3600 IN A 192.168.1.10\n",
	)
	z, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(z.Records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(z.Records))
	}
	if z.Origin != "example.com" {
		t.Errorf("expected origin example.com, got %q", z.Origin)
	}
	a1, ok := z.Records[0].(*packet.DNSResourceRecordA)
	if !ok {
		t.Fatalf("expected A record, got %T", z.Records[0])
	}
	if a1.Name != "example.com" {
		t.Errorf("expected @ to resolve to %q, got %q", "example.com", a1.Name)
	}
	a2, ok := z.Records[1].(*packet.DNSResourceRecordA)
	if !ok {
		t.Fatalf("expected A record, got %T", z.Records[1])
	}
	if a2.Name != "www.example.com" {
		t.Errorf("expected www.example.com, got %q", a2.Name)
	}
}

func TestParseWithTTLDirective(t *testing.T) {
	data := []byte(
		"$TTL 7200\n" +
			"example.com. IN A 192.168.1.1\n",
	)
	z, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if z.TTL != 7200 {
		t.Errorf("expected TTL 7200, got %d", z.TTL)
	}
	a, ok := z.Records[0].(*packet.DNSResourceRecordA)
	if !ok {
		t.Fatalf("expected A record, got %T", z.Records[0])
	}
	if a.TTL != 7200 {
		t.Errorf("expected TTL 7200, got %d", a.TTL)
	}
}

func TestParseTTLInheritance(t *testing.T) {
	data := []byte(
		"$TTL 3600\n" +
			"example.com. IN A 192.168.1.1\n" +
			"www.example.com. 7200 IN A 192.168.1.10\n" +
			"mail.example.com. IN A 192.168.1.20\n",
	)
	z, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(z.Records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(z.Records))
	}
	recs := z.Records
	if r := recs[0].(*packet.DNSResourceRecordA); r.TTL != 3600 {
		t.Errorf("record 0: expected TTL 3600, got %d", r.TTL)
	}
	if r := recs[1].(*packet.DNSResourceRecordA); r.TTL != 7200 {
		t.Errorf("record 1: expected TTL 7200, got %d", r.TTL)
	}
	if r := recs[2].(*packet.DNSResourceRecordA); r.TTL != 7200 {
		t.Errorf("record 2: expected TTL 7200 (inherited from prev), got %d", r.TTL)
	}
}

func TestParseComments(t *testing.T) {
	data := []byte(
		"; This is a comment\n" +
			"# Another comment style\n" +
			"example.com. 3600 IN A 192.168.1.1 ; inline comment\n",
	)
	z, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(z.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(z.Records))
	}
}

func TestParseEmptyInput(t *testing.T) {
	z, err := Parse([]byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(z.Records) != 0 {
		t.Errorf("expected 0 records, got %d", len(z.Records))
	}
}

func TestParseCommentsOnly(t *testing.T) {
	z, err := Parse([]byte("; just a comment\n# another comment\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(z.Records) != 0 {
		t.Errorf("expected 0 records, got %d", len(z.Records))
	}
}

func TestParseTTLSuffixes(t *testing.T) {
	tests := []struct {
		input string
		ttl   uint32
	}{
		{"3600", 3600},
		{"1H", 3600},
		{"30M", 1800},
		{"2D", 172800},
		{"1W", 604800},
		{"3600S", 3600},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			data := []byte("example.com. " + tt.input + " IN A 192.168.1.1\n")
			z, err := Parse(data)
			if err != nil {
				t.Fatal(err)
			}
			a := z.Records[0].(*packet.DNSResourceRecordA)
			if a.TTL != tt.ttl {
				t.Errorf("expected TTL %d, got %d", tt.ttl, a.TTL)
			}
		})
	}
}

func TestParseFileNotExist(t *testing.T) {
	_, err := ParseFile("/nonexistent/zone.file")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestParseRejectsIncompleteRecordWithoutPanicking(t *testing.T) {
	inputs := []string{
		"example.com. 3600\n",
		"example.com. IN\n",
		"example.com.\n",
	}
	for _, input := range inputs {
		if _, err := Parse([]byte(input)); err == nil {
			t.Errorf("expected error for incomplete record %q", input)
		}
	}
}

func TestParseRejectsTTLOverflow(t *testing.T) {
	if _, err := Parse([]byte("example.com. 4294967295W IN A 192.0.2.1\n")); err == nil {
		t.Fatal("expected overflowing TTL to be rejected")
	}
}

func TestParseRejectsIPv4InAAAA(t *testing.T) {
	if _, err := Parse([]byte("example.com. IN AAAA 192.0.2.1\n")); err == nil {
		t.Fatal("expected IPv4 address in AAAA record to be rejected")
	}
}

func TestParseModernResourceRecords(t *testing.T) {
	data := []byte("example.com. 300 IN CAA 0 issue \"letsencrypt.org\"\n" +
		"child.example.com. 300 IN DS 12345 13 2 AABBCCDD\n" +
		"example.com. 300 IN DNSKEY 257 3 13 AQIDBA==\n" +
		"example.com. 300 IN RRSIG A 13 2 300 2000000000 1900000000 12345 example.com. AQIDBA==\n" +
		"example.com. 300 IN NSEC next.example.com. A RRSIG CAA\n" +
		"_443._tcp.example.com. 300 IN TLSA 3 1 1 DEADBEEF\n" +
		"example.com. 300 IN HTTPS 1 svc.example.com. mandatory=alpn,port alpn=\"h2,h3\" port=443 ipv4hint=192.0.2.1\n")
	z, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(z.Records) != 7 {
		t.Fatalf("got %d records, want 7", len(z.Records))
	}
	if caa := z.Records[0].(*packet.DNSResourceRecordCAA); caa.Tag != "issue" || caa.Value != "letsencrypt.org" {
		t.Fatalf("unexpected CAA: %#v", caa)
	}
	if ds := z.Records[1].(*packet.DNSResourceRecordDS); ds.KeyTag != 12345 || len(ds.Digest) != 4 {
		t.Fatalf("unexpected DS: %#v", ds)
	}
	if key := z.Records[2].(*packet.DNSResourceRecordDNSKEY); key.Flags != 257 || len(key.PublicKey) != 4 {
		t.Fatalf("unexpected DNSKEY: %#v", key)
	}
	if sig := z.Records[3].(*packet.DNSResourceRecordRRSIG); sig.TypeCovered != packet.DNSTypeA || sig.KeyTag != 12345 {
		t.Fatalf("unexpected RRSIG: %#v", sig)
	}
	if nsec := z.Records[4].(*packet.DNSResourceRecordNSEC); len(nsec.Types) != 3 || nsec.Types[2] != packet.DNSTypeCAA {
		t.Fatalf("unexpected NSEC: %#v", nsec)
	}
	if tlsa := z.Records[5].(*packet.DNSResourceRecordTLSA); len(tlsa.CertificateAssociationData) != 4 {
		t.Fatalf("unexpected TLSA: %#v", tlsa)
	}
	if https := z.Records[6].(*packet.DNSResourceRecordSVCB); https.Type != packet.DNSTypeHTTPS || len(https.Params) != 4 || https.Params[0].Key != 0 {
		t.Fatalf("unexpected HTTPS: %#v", https)
	}
}

func TestParseRejectsInvalidSVCBParameters(t *testing.T) {
	inputs := []string{
		"example.com. IN SVCB 0 alias.example.com. alpn=h2\n",
		"example.com. IN HTTPS 1 . port=443 port=8443\n",
		"example.com. IN HTTPS 1 . mandatory=alpn port=443\n",
		"example.com. IN HTTPS 1 . mandatory=alpn,alpn alpn=h2\n",
		"example.com. IN HTTPS 1 . no-default-alpn\n",
		"example.com. IN CAA 0 issue-wild ca.example\n",
	}
	for _, input := range inputs {
		if _, err := Parse([]byte(input)); err == nil {
			t.Errorf("expected invalid SVCB record to fail: %s", input)
		}
	}
}
