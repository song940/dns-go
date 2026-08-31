package packet

import (
	"bytes"
	"fmt"
	"io"
	"net"
)

type DNSResourceRecordA struct {
	DNSResourceRecord

	Address string
}

// decode implements DNSResourceRecordData.
func (a *DNSResourceRecordA) Decode(reader *bytes.Reader, length uint16) error {
	if length != net.IPv4len {
		return fmt.Errorf("A RDATA length is %d, want 4", length)
	}
	data := make([]byte, net.IPv4len)
	if _, err := io.ReadFull(reader, data); err != nil {
		return err
	}
	a.Address = net.IP(data).String()
	return nil
}

func (a *DNSResourceRecordA) Encode() []byte {
	return net.ParseIP(a.Address).To4()
}

func (a *DNSResourceRecordA) Bytes() []byte {
	return a.WrapData(a.Encode())
}
