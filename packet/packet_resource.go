package packet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// DNSType defines the type of data being requested/returned in a
// question/answer.
type DNSType uint16

// https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
const (
	DNSTypeA      DNSType = 0x0001 // a host address
	DNSTypeNS     DNSType = 0x0002 // an authoritative name server
	DNSTypeMD     DNSType = 0x0003 // a mail destination (Obsolete - use MX)
	DNSTypeMF     DNSType = 0x04   // a mail forwarder (Obsolete - use MX)
	DNSTypeCNAME  DNSType = 0x05   // the canonical name for an alias
	DNSTypeSOA    DNSType = 0x06   // marks the start of a zone of authority
	DNSTypeMB     DNSType = 0x07   // a mailbox domain name (EXPERIMENTAL)
	DNSTypeMG     DNSType = 0x08   // a mail group member (EXPERIMENTAL)
	DNSTypeMR     DNSType = 0x09   // a mail rename domain name (EXPERIMENTAL)
	DNSTypeNULL   DNSType = 0x0A   // a null RR (EXPERIMENTAL)
	DNSTypeWKS    DNSType = 0x0B   // a well known service description
	DNSTypePTR    DNSType = 0x0C   // a domain name pointer
	DNSTypeHINFO  DNSType = 0x0D   // host information
	DNSTypeMINFO  DNSType = 0x0E   // mailbox or mail list information
	DNSTypeMX     DNSType = 0x0F   // mail exchange
	DNSTypeTXT    DNSType = 0x10   // text strings
	DNSTypeAAAA   DNSType = 0x1C   // a ipv6 host address
	DNSTypeSRV    DNSType = 0x21   // a service location
	DNSTypeEDNS   DNSType = 0x29   // extensible dns
	DNSTypeDS     DNSType = 0x2B   // delegation signer
	DNSTypeRRSIG  DNSType = 0x2E   // DNSSEC signature
	DNSTypeNSEC   DNSType = 0x2F   // authenticated denial of existence
	DNSTypeDNSKEY DNSType = 0x30   // DNSSEC public key
	DNSTypeTLSA   DNSType = 0x34   // TLS certificate association
	DNSTypeSVCB   DNSType = 0x40   // service binding
	DNSTypeHTTPS  DNSType = 0x41   // HTTPS service binding
	DNSTypeSPF    DNSType = 0x63   // a Sender Policy Framework record
	DNSTypeCAA    DNSType = 0x101  // certification authority authorization
	DNSTypeAXFR   DNSType = 0xFC   // A request for a transfer of an entire zone
	DNSTypeMAILB  DNSType = 0xFD   // A request for mailbox-related records (MB, MG or MR)
	DNSTypeMAILA  DNSType = 0xFE   // A request for mail agent RRs (Obsolete - see MX)
	DNSTypeAny    DNSType = 0xFF   // A request for all records
)

// DNSClass defines the class associated with a request/response.  Different DNS
// classes can be thought of as an array of parallel namespace trees.
type DNSClass uint16

// DNSClass known values.
const (
	DNSClassIN  DNSClass = 0x01 // Internet
	DNSClassCS  DNSClass = 0x02 // the CSNET class (Obsolete)
	DNSClassCH  DNSClass = 0x03 // the CHAOS class
	DNSClassHS  DNSClass = 0x04 // Hesiod [Dyer 87]
	DNSClassAny DNSClass = 0xFF // AnyClass
)

func (dc DNSClass) String() string {
	switch dc {
	default:
		return "Unknown"
	case DNSClassIN:
		return "IN"
	case DNSClassCS:
		return "CS"
	case DNSClassCH:
		return "CH"
	case DNSClassHS:
		return "HS"
	case DNSClassAny:
		return "Any"
	}
}

// DNSOpCode defines a set of different operation types.
type DNSOpCode uint8

// DNSOpCode known values.
const (
	DNSOpCodeQuery  DNSOpCode = 0 // Query                  [RFC1035]
	DNSOpCodeIQuery DNSOpCode = 1 // Inverse Query Obsolete [RFC3425]
	DNSOpCodeStatus DNSOpCode = 2 // Status                 [RFC1035]
	DNSOpCodeNotify DNSOpCode = 4 // Notify                 [RFC1996]
	DNSOpCodeUpdate DNSOpCode = 5 // Update                 [RFC2136]
)

func (code DNSOpCode) String() string {
	switch code {
	case DNSOpCodeQuery:
		return "Query"
	case DNSOpCodeIQuery:
		return "Inverse Query"
	case DNSOpCodeStatus:
		return "Status"
	case DNSOpCodeNotify:
		return "Notify"
	case DNSOpCodeUpdate:
		return "Update"
	default:
		return "Unknown"
	}
}

type DNSResource interface {
	Bytes() []byte
	GetType() DNSType
	Encode() []byte
	Decode(reader *bytes.Reader, length uint16) error
}

// DNSResourceRecord
// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                                               |
// /                                               /
// /                      NAME                     /
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      TYPE                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     CLASS                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      TTL                      |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                   RDLENGTH                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
// /                     RDATA                     /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type DNSResourceRecord struct {
	Name  string
	Type  DNSType
	Class DNSClass
	TTL   uint32
}

func (r *DNSResourceRecord) GetType() DNSType {
	return r.Type
}

func ParseResource(reader *bytes.Reader) (record DNSResource, err error) {
	r := DNSResourceRecord{}
	if r.Name, err = decodeDomainName(reader); err != nil {
		return
	}
	if err = binary.Read(reader, binary.BigEndian, &r.Type); err != nil {
		return
	}
	if err = binary.Read(reader, binary.BigEndian, &r.Class); err != nil {
		return
	}
	if err = binary.Read(reader, binary.BigEndian, &r.TTL); err != nil {
		return
	}
	switch r.Type {
	case DNSTypeA:
		record = &DNSResourceRecordA{
			DNSResourceRecord: r,
		}
	case DNSTypeAAAA:
		record = &DNSResourceRecordAAAA{
			DNSResourceRecord: r,
		}
	case DNSTypeSOA:
		record = &DNSResourceRecordSOA{
			DNSResourceRecord: r,
		}
	case DNSTypeTXT:
		record = &DNSResourceRecordTXT{
			DNSResourceRecord: r,
		}
	case DNSTypeNS:
		record = &DNSResourceRecordNS{
			DNSResourceRecord: r,
		}
	case DNSTypeSRV:
		record = &DNSResourceRecordSRV{
			DNSResourceRecord: r,
		}
	case DNSTypeCNAME:
		record = &DNSResourceRecordCNAME{
			DNSResourceRecord: r,
		}
	case DNSTypeEDNS:
		record = &DNSResourceRecordEDNS{
			DNSResourceRecord: r,
		}
	case DNSTypeMX:
		record = &DNSResourceRecordMX{
			DNSResourceRecord: r,
		}
	case DNSTypePTR:
		record = &DNSResourceRecordPTR{
			DNSResourceRecord: r,
		}
	case DNSTypeCAA:
		record = &DNSResourceRecordCAA{DNSResourceRecord: r}
	case DNSTypeDS:
		record = &DNSResourceRecordDS{DNSResourceRecord: r}
	case DNSTypeDNSKEY:
		record = &DNSResourceRecordDNSKEY{DNSResourceRecord: r}
	case DNSTypeRRSIG:
		record = &DNSResourceRecordRRSIG{DNSResourceRecord: r}
	case DNSTypeNSEC:
		record = &DNSResourceRecordNSEC{DNSResourceRecord: r}
	case DNSTypeTLSA:
		record = &DNSResourceRecordTLSA{DNSResourceRecord: r}
	case DNSTypeSVCB, DNSTypeHTTPS:
		record = &DNSResourceRecordSVCB{DNSResourceRecord: r}
	default:
		record = &DNSResourceRecordUnknown{
			DNSResourceRecord: r,
		}
	}
	// Read RDLENGTH
	var rdLength uint16
	if err = binary.Read(reader, binary.BigEndian, &rdLength); err != nil {
		return
	}
	if int(rdLength) > reader.Len() {
		return nil, fmt.Errorf("RDLENGTH %d exceeds remaining message size %d", rdLength, reader.Len())
	}
	start, err := reader.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	if err = record.Decode(reader, rdLength); err != nil {
		return nil, fmt.Errorf("decode type %d RDATA: %w", r.Type, err)
	}
	end, err := reader.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	if consumed := end - start; consumed != int64(rdLength) {
		return nil, fmt.Errorf("type %d decoder consumed %d bytes, RDLENGTH is %d", r.Type, consumed, rdLength)
	}
	return
}

func (r *DNSResourceRecord) WrapData(rdData []byte) []byte {
	var buf bytes.Buffer
	// Encode domain name
	encodeDomainName(&buf, r.Name, true)
	// Encode type
	binary.Write(&buf, binary.BigEndian, uint16(r.Type))
	// Encode class
	binary.Write(&buf, binary.BigEndian, uint16(r.Class))
	// Encode TTL
	binary.Write(&buf, binary.BigEndian, r.TTL)
	// RDLENGTH (2 bytes)
	rdLength := uint16(len(rdData))
	binary.Write(&buf, binary.BigEndian, rdLength)
	// Write Data
	buf.Write(rdData)
	return buf.Bytes()
}
