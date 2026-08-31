package packet

import (
	"bytes"
	"encoding/binary"
)

// SOA RDATA format
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// /                     MNAME                     /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// /                     RNAME                     /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    SERIAL                     |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    REFRESH                    |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     RETRY                     |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    EXPIRE                     |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    MINIMUM                    |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// DNSResourceRecordSOA represents the SOA resource record data.
type DNSResourceRecordSOA struct {
	DNSResourceRecord
	MName   string
	RName   string
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32
}

func (d *DNSResourceRecordSOA) Decode(reader *bytes.Reader, length uint16) (err error) {
	if d.MName, err = decodeDomainName(reader); err != nil {
		return err
	}
	if d.RName, err = decodeDomainName(reader); err != nil {
		return err
	}
	for _, value := range []any{&d.Serial, &d.Refresh, &d.Retry, &d.Expire, &d.Minimum} {
		if err = binary.Read(reader, binary.BigEndian, value); err != nil {
			return err
		}
	}
	return nil
}

func (d *DNSResourceRecordSOA) Encode() []byte {
	var buf bytes.Buffer
	encodeDomainName(&buf, d.MName, true)
	encodeDomainName(&buf, d.RName, true)
	// Serial
	binary.Write(&buf, binary.BigEndian, d.Serial)
	// Refresh
	binary.Write(&buf, binary.BigEndian, d.Refresh)
	// Retry
	binary.Write(&buf, binary.BigEndian, d.Retry)
	// Expire
	binary.Write(&buf, binary.BigEndian, d.Expire)
	// Minimum
	binary.Write(&buf, binary.BigEndian, d.Minimum)
	return buf.Bytes()
}

func (a *DNSResourceRecordSOA) Bytes() []byte {
	return a.WrapData(a.Encode())
}
