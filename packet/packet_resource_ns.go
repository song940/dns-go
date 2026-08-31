package packet

import (
	"bytes"
)

type DNSResourceRecordNS struct {
	DNSResourceRecord

	NameServer string
}

// Decode implements DNSResource.
func (d *DNSResourceRecordNS) Decode(reader *bytes.Reader, length uint16) (err error) {
	d.NameServer, err = decodeDomainName(reader)
	return err
}

// Encode implements DNSResource.
// Subtle: this method shadows the method (DNSResourceRecord).Encode of DNSResourceRecordNS.DNSResourceRecord.
func (d *DNSResourceRecordNS) Encode() []byte {
	var buf bytes.Buffer
	encodeDomainName(&buf, d.NameServer, true)
	return buf.Bytes()
}

func (a *DNSResourceRecordNS) Bytes() []byte {
	return a.WrapData(a.Encode())
}
