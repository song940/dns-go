package packet

import (
	"bytes"
	"encoding/binary"
)

// MX RDATA format
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                   PREFERENCE                  |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// /                   EXCHANGE                    /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// DNSResourceRecordMX represents the MX (Mail Exchange) resource record.
// MX records specify the mail server responsible for accepting email messages on behalf of a domain.
type DNSResourceRecordMX struct {
	DNSResourceRecord

	Preference uint16 // The priority of the mail server (lower value = higher priority)
	Exchange   string // The domain name of the mail server
}

// Decode implements DNSResource.
func (r *DNSResourceRecordMX) Decode(reader *bytes.Reader, length uint16) (err error) {
	if err = binary.Read(reader, binary.BigEndian, &r.Preference); err != nil {
		return err
	}
	r.Exchange, err = decodeDomainName(reader)
	return err
}

// Encode implements DNSResource.
func (r *DNSResourceRecordMX) Encode() []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, r.Preference)
	encodeDomainName(&buf, r.Exchange, true)
	return buf.Bytes()
}

func (r *DNSResourceRecordMX) Bytes() []byte {
	return r.WrapData(r.Encode())
}
