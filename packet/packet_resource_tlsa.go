package packet

import (
	"bytes"
	"fmt"
	"io"
)

type DNSResourceRecordTLSA struct {
	DNSResourceRecord
	Usage                      uint8
	Selector                   uint8
	MatchingType               uint8
	CertificateAssociationData []byte
}

func (r *DNSResourceRecordTLSA) Decode(reader *bytes.Reader, length uint16) error {
	if length < 3 {
		return fmt.Errorf("TLSA RDATA is too short: %d", length)
	}
	var err error
	if r.Usage, err = reader.ReadByte(); err != nil {
		return err
	}
	if r.Selector, err = reader.ReadByte(); err != nil {
		return err
	}
	if r.MatchingType, err = reader.ReadByte(); err != nil {
		return err
	}
	r.CertificateAssociationData = make([]byte, int(length)-3)
	_, err = io.ReadFull(reader, r.CertificateAssociationData)
	return err
}

func (r *DNSResourceRecordTLSA) Encode() []byte {
	return append([]byte{r.Usage, r.Selector, r.MatchingType}, r.CertificateAssociationData...)
}

func (r *DNSResourceRecordTLSA) Bytes() []byte { return r.WrapData(r.Encode()) }
