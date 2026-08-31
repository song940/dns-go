package packet

import (
	"bytes"
)

// DNSResourceRecordPTR represents the PTR (Pointer) resource record.
// PTR records are used for reverse DNS lookups, mapping IP addresses to domain names.
type DNSResourceRecordPTR struct {
	DNSResourceRecord

	PtrDomainName string // The domain name that the IP address points to
}

// Decode implements DNSResource.
func (r *DNSResourceRecordPTR) Decode(reader *bytes.Reader, length uint16) (err error) {
	r.PtrDomainName, err = decodeDomainName(reader)
	return err
}

// Encode implements DNSResource.
func (r *DNSResourceRecordPTR) Encode() []byte {
	var buf bytes.Buffer
	encodeDomainName(&buf, r.PtrDomainName, true)
	return buf.Bytes()
}

func (r *DNSResourceRecordPTR) Bytes() []byte {
	return r.WrapData(r.Encode())
}
