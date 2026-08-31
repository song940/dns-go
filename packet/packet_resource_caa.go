package packet

import (
	"bytes"
	"fmt"
	"io"
)

type DNSResourceRecordCAA struct {
	DNSResourceRecord
	Flags uint8
	Tag   string
	Value string
}

func (r *DNSResourceRecordCAA) Decode(reader *bytes.Reader, length uint16) error {
	if length < 2 {
		return fmt.Errorf("CAA RDATA is too short: %d", length)
	}
	flags, err := reader.ReadByte()
	if err != nil {
		return err
	}
	tagLength, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if tagLength == 0 || int(tagLength) > int(length)-2 {
		return fmt.Errorf("invalid CAA tag length %d for RDATA length %d", tagLength, length)
	}
	tag := make([]byte, int(tagLength))
	if _, err := io.ReadFull(reader, tag); err != nil {
		return err
	}
	for _, ch := range tag {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) {
			return fmt.Errorf("invalid CAA tag byte %#x", ch)
		}
	}
	value := make([]byte, int(length)-2-int(tagLength))
	if _, err := io.ReadFull(reader, value); err != nil {
		return err
	}
	r.Flags, r.Tag, r.Value = flags, string(tag), string(value)
	return nil
}

func (r *DNSResourceRecordCAA) Encode() []byte {
	var buf bytes.Buffer
	buf.WriteByte(r.Flags)
	buf.WriteByte(byte(len(r.Tag)))
	buf.WriteString(r.Tag)
	buf.WriteString(r.Value)
	return buf.Bytes()
}

func (r *DNSResourceRecordCAA) Bytes() []byte { return r.WrapData(r.Encode()) }
