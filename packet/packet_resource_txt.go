package packet

import (
	"bytes"
	"fmt"
	"io"
)

type DNSResourceRecordTXT struct {
	DNSResourceRecord

	Content string
}

// Decode implements DNSResource.
func (d *DNSResourceRecordTXT) Decode(reader *bytes.Reader, length uint16) error {
	remaining := int(length)
	var content bytes.Buffer
	for remaining > 0 {
		segmentLength, err := reader.ReadByte()
		if err != nil {
			return err
		}
		remaining--
		if int(segmentLength) > remaining {
			return fmt.Errorf("TXT segment length %d exceeds remaining RDATA %d", segmentLength, remaining)
		}
		segment := make([]byte, int(segmentLength))
		if _, err := io.ReadFull(reader, segment); err != nil {
			return err
		}
		remaining -= int(segmentLength)
		content.Write(segment)
	}
	d.Content = content.String()
	return nil
}

// Encode implements DNSResource.
// Subtle: this method shadows the method (DNSResourceRecord).Encode of DNSResourceRecordTXT.DNSResourceRecord.
func (d *DNSResourceRecordTXT) Encode() []byte {
	var buf bytes.Buffer
	data := []byte(d.Content)
	for len(data) > 0 {
		length := len(data)
		if length > 255 {
			length = 255
		}
		buf.WriteByte(byte(length))
		buf.Write(data[:length])
		data = data[length:]
	}
	if len(d.Content) == 0 {
		buf.WriteByte(0)
	}
	return buf.Bytes()
}

func (a *DNSResourceRecordTXT) Bytes() []byte {
	return a.WrapData(a.Encode())
}
