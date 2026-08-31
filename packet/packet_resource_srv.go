package packet

import (
	"bytes"
	"encoding/binary"
)

type DNSResourceRecordSRV struct {
	DNSResourceRecord

	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}

// Decode implements DNSResource.
func (d *DNSResourceRecordSRV) Decode(reader *bytes.Reader, length uint16) (err error) {
	for _, value := range []any{&d.Priority, &d.Weight, &d.Port} {
		if err = binary.Read(reader, binary.BigEndian, value); err != nil {
			return err
		}
	}
	d.Target, err = decodeDomainName(reader)
	return err
}

// Encode implements DNSResource.
// Subtle: this method shadows the method (DNSResourceRecord).Encode of DNSResourceRecordSRV.DNSResourceRecord.
func (d *DNSResourceRecordSRV) Encode() []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, d.Priority)
	binary.Write(&buf, binary.BigEndian, d.Weight)
	binary.Write(&buf, binary.BigEndian, d.Port)
	encodeDomainName(&buf, d.Target, true)
	return buf.Bytes()
}

func (a *DNSResourceRecordSRV) Bytes() []byte {
	return a.WrapData(a.Encode())
}
