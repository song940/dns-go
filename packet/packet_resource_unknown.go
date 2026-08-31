package packet

import (
	"bytes"
	"io"
)

// DNSResourceRecordUnknown represents an unknown or unsupported resource record type.
// It stores the raw RDATA bytes for potential future processing.
type DNSResourceRecordUnknown struct {
	DNSResourceRecord
	RData []byte
}

func (r *DNSResourceRecordUnknown) Decode(reader *bytes.Reader, length uint16) error {
	// Read RDATA bytes
	r.RData = make([]byte, length)
	_, err := io.ReadFull(reader, r.RData)
	return err
}

func (r *DNSResourceRecordUnknown) Encode() []byte {
	return r.RData
}

func (r *DNSResourceRecordUnknown) Bytes() []byte {
	return r.WrapData(r.RData)
}
