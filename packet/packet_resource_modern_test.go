package packet

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

func TestModernResourceRoundTrip(t *testing.T) {
	base := func(rtype DNSType) DNSResourceRecord {
		return DNSResourceRecord{Name: "example.com", Type: rtype, Class: DNSClassIN, TTL: 300}
	}
	records := []DNSResource{
		&DNSResourceRecordCAA{DNSResourceRecord: base(DNSTypeCAA), Flags: 0, Tag: "issue", Value: "ca.example"},
		&DNSResourceRecordDS{DNSResourceRecord: base(DNSTypeDS), KeyTag: 12345, Algorithm: 13, DigestType: 2, Digest: []byte{1, 2, 3, 4}},
		&DNSResourceRecordDNSKEY{DNSResourceRecord: base(DNSTypeDNSKEY), Flags: 257, Protocol: 3, Algorithm: 13, PublicKey: []byte{5, 6, 7}},
		&DNSResourceRecordRRSIG{DNSResourceRecord: base(DNSTypeRRSIG), TypeCovered: DNSTypeA, Algorithm: 13, Labels: 2, OriginalTTL: 300, Expiration: 2_000_000_000, Inception: 1_900_000_000, KeyTag: 12345, SignerName: "example.com", Signature: []byte{8, 9, 10}},
		&DNSResourceRecordNSEC{DNSResourceRecord: base(DNSTypeNSEC), NextDomain: "next.example.com", Types: []DNSType{DNSTypeA, DNSTypeRRSIG, DNSTypeCAA}},
		&DNSResourceRecordTLSA{DNSResourceRecord: base(DNSTypeTLSA), Usage: 3, Selector: 1, MatchingType: 1, CertificateAssociationData: []byte{0xde, 0xad, 0xbe, 0xef}},
		&DNSResourceRecordSVCB{DNSResourceRecord: base(DNSTypeSVCB), Priority: 1, Target: "svc.example.com", Params: []SVCBParam{{Key: 1, Value: []byte{2, 'h', '2'}}, {Key: 3, Value: []byte{1, 187}}}},
		&DNSResourceRecordSVCB{DNSResourceRecord: base(DNSTypeHTTPS), Priority: 1, Target: ".", Params: []SVCBParam{{Key: 1, Value: []byte{2, 'h', '2'}}, {Key: 2, Value: []byte{}}}},
	}

	p := NewPacket()
	p.Answers = records
	decoded, err := FromBytes(p.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	for i := range records {
		if !reflect.DeepEqual(decoded.Answers[i], records[i]) {
			t.Fatalf("record %d round trip mismatch:\n got: %+v\nwant: %+v", i, decoded.Answers[i], records[i])
		}
	}
}

func TestTXTRoundTripUsesCharacterStrings(t *testing.T) {
	content := strings.Repeat("x", 300)
	record := &DNSResourceRecordTXT{
		DNSResourceRecord: DNSResourceRecord{Name: "example.com", Type: DNSTypeTXT, Class: DNSClassIN, TTL: 60},
		Content:           content,
	}
	p := NewPacket()
	p.AddAnswer(record)
	decoded, err := FromBytes(p.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if got := decoded.Answers[0].(*DNSResourceRecordTXT).Content; got != content {
		t.Fatalf("TXT content length=%d, want %d", len(got), len(content))
	}
	encoded := record.Encode()
	if len(encoded) != 302 || encoded[0] != 255 || encoded[256] != 45 {
		previewLength := len(encoded)
		if previewLength > 258 {
			previewLength = 258
		}
		t.Fatalf("invalid character-string segmentation: %v", encoded[:previewLength])
	}
}

func TestParseResourceRejectsInvalidRDataLengths(t *testing.T) {
	tests := []struct {
		name  string
		type_ DNSType
		data  []byte
	}{
		{name: "short A", type_: DNSTypeA, data: []byte{192, 0, 2}},
		{name: "empty CAA tag", type_: DNSTypeCAA, data: []byte{0, 0}},
		{name: "CAA tag beyond RDATA", type_: DNSTypeCAA, data: []byte{0, 4, 'i'}},
		{name: "truncated EDNS option", type_: DNSTypeEDNS, data: []byte{0, 1, 0, 2, 0}},
		{name: "SVCB alias parameters", type_: DNSTypeSVCB, data: []byte{0, 0, 0, 0, 1, 0, 3, 2, 'h', '2'}},
		{name: "SVCB no-default-alpn without alpn", type_: DNSTypeHTTPS, data: []byte{0, 1, 0, 0, 2, 0, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wire bytes.Buffer
			wire.Write((&DNSHeader{ANCount: 1}).Bytes())
			wire.WriteByte(0)
			_ = binary.Write(&wire, binary.BigEndian, tt.type_)
			_ = binary.Write(&wire, binary.BigEndian, DNSClassIN)
			_ = binary.Write(&wire, binary.BigEndian, uint32(60))
			_ = binary.Write(&wire, binary.BigEndian, uint16(len(tt.data)))
			wire.Write(tt.data)
			if _, err := FromBytes(wire.Bytes()); err == nil {
				t.Fatal("expected malformed RDATA to be rejected")
			}
		})
	}
}
