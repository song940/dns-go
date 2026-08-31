package packet

import (
	"bytes"
)

type DNSResourceRecordCNAME struct {
	DNSResourceRecord

	Domain string
}

// Decode implements DNSResource.
func (d *DNSResourceRecordCNAME) Decode(reader *bytes.Reader, length uint16) (err error) {
	d.Domain, err = decodeDomainName(reader)
	return err
}

// Encode implements DNSResource.
// Subtle: this method shadows the method (DNSResourceRecord).Encode of DNSResourceRecordCNAME.DNSResourceRecord.
func (d *DNSResourceRecordCNAME) Encode() []byte {
	var buf bytes.Buffer
	encodeDomainName(&buf, d.Domain, true)
	return buf.Bytes()
}

func (a *DNSResourceRecordCNAME) Bytes() []byte {
	return a.WrapData(a.Encode())
}
