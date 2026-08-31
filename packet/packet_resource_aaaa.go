package packet

import (
	"bytes"
	"fmt"
	"io"
	"net"
)

type DNSResourceRecordAAAA struct {
	DNSResourceRecord

	Address string
}

// Decode implements DNSResource.
func (d *DNSResourceRecordAAAA) Decode(reader *bytes.Reader, length uint16) error {
	if length != net.IPv6len {
		return fmt.Errorf("AAAA RDATA length is %d, want 16", length)
	}
	data := make([]byte, net.IPv6len)
	if _, err := io.ReadFull(reader, data); err != nil {
		return err
	}
	d.Address = net.IP(data).String()
	return nil
}

func (d *DNSResourceRecordAAAA) Encode() []byte {
	return net.ParseIP(d.Address).To16()
}

func (a *DNSResourceRecordAAAA) Bytes() []byte {
	return a.WrapData(a.Encode())
}
