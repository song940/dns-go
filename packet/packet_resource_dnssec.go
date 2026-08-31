package packet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
)

type DNSResourceRecordDS struct {
	DNSResourceRecord
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     []byte
}

func (r *DNSResourceRecordDS) Decode(reader *bytes.Reader, length uint16) error {
	if length < 4 {
		return fmt.Errorf("DS RDATA is too short: %d", length)
	}
	if err := binary.Read(reader, binary.BigEndian, &r.KeyTag); err != nil {
		return err
	}
	algorithm, err := reader.ReadByte()
	if err != nil {
		return err
	}
	digestType, err := reader.ReadByte()
	if err != nil {
		return err
	}
	r.Algorithm, r.DigestType = algorithm, digestType
	r.Digest = make([]byte, int(length)-4)
	_, err = io.ReadFull(reader, r.Digest)
	return err
}

func (r *DNSResourceRecordDS) Encode() []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, r.KeyTag)
	buf.WriteByte(r.Algorithm)
	buf.WriteByte(r.DigestType)
	buf.Write(r.Digest)
	return buf.Bytes()
}

func (r *DNSResourceRecordDS) Bytes() []byte { return r.WrapData(r.Encode()) }

type DNSResourceRecordDNSKEY struct {
	DNSResourceRecord
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey []byte
}

func (r *DNSResourceRecordDNSKEY) Decode(reader *bytes.Reader, length uint16) error {
	if length < 4 {
		return fmt.Errorf("DNSKEY RDATA is too short: %d", length)
	}
	if err := binary.Read(reader, binary.BigEndian, &r.Flags); err != nil {
		return err
	}
	protocol, err := reader.ReadByte()
	if err != nil {
		return err
	}
	algorithm, err := reader.ReadByte()
	if err != nil {
		return err
	}
	r.Protocol, r.Algorithm = protocol, algorithm
	r.PublicKey = make([]byte, int(length)-4)
	_, err = io.ReadFull(reader, r.PublicKey)
	return err
}

func (r *DNSResourceRecordDNSKEY) Encode() []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, r.Flags)
	buf.WriteByte(r.Protocol)
	buf.WriteByte(r.Algorithm)
	buf.Write(r.PublicKey)
	return buf.Bytes()
}

func (r *DNSResourceRecordDNSKEY) Bytes() []byte { return r.WrapData(r.Encode()) }

type DNSResourceRecordRRSIG struct {
	DNSResourceRecord
	TypeCovered DNSType
	Algorithm   uint8
	Labels      uint8
	OriginalTTL uint32
	Expiration  uint32
	Inception   uint32
	KeyTag      uint16
	SignerName  string
	Signature   []byte
}

func (r *DNSResourceRecordRRSIG) Decode(reader *bytes.Reader, length uint16) (err error) {
	if length < 19 {
		return fmt.Errorf("RRSIG RDATA is too short: %d", length)
	}
	start := reader.Len()
	if err = binary.Read(reader, binary.BigEndian, &r.TypeCovered); err != nil {
		return err
	}
	if r.Algorithm, err = reader.ReadByte(); err != nil {
		return err
	}
	if r.Labels, err = reader.ReadByte(); err != nil {
		return err
	}
	for _, value := range []any{&r.OriginalTTL, &r.Expiration, &r.Inception, &r.KeyTag} {
		if err = binary.Read(reader, binary.BigEndian, value); err != nil {
			return err
		}
	}
	if r.SignerName, err = decodeDomainName(reader); err != nil {
		return err
	}
	consumed := start - reader.Len()
	remaining := int(length) - consumed
	if remaining < 0 {
		return fmt.Errorf("RRSIG signer name exceeds RDLENGTH")
	}
	r.Signature = make([]byte, remaining)
	_, err = io.ReadFull(reader, r.Signature)
	return err
}

func (r *DNSResourceRecordRRSIG) Encode() []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, r.TypeCovered)
	buf.WriteByte(r.Algorithm)
	buf.WriteByte(r.Labels)
	_ = binary.Write(&buf, binary.BigEndian, r.OriginalTTL)
	_ = binary.Write(&buf, binary.BigEndian, r.Expiration)
	_ = binary.Write(&buf, binary.BigEndian, r.Inception)
	_ = binary.Write(&buf, binary.BigEndian, r.KeyTag)
	encodeDomainName(&buf, r.SignerName, true)
	buf.Write(r.Signature)
	return buf.Bytes()
}

func (r *DNSResourceRecordRRSIG) Bytes() []byte { return r.WrapData(r.Encode()) }

type DNSResourceRecordNSEC struct {
	DNSResourceRecord
	NextDomain string
	Types      []DNSType
}

func (r *DNSResourceRecordNSEC) Decode(reader *bytes.Reader, length uint16) (err error) {
	start := reader.Len()
	if r.NextDomain, err = decodeDomainName(reader); err != nil {
		return err
	}
	remaining := int(length) - (start - reader.Len())
	lastWindow := -1
	for remaining > 0 {
		if remaining < 2 {
			return fmt.Errorf("NSEC bitmap header is truncated")
		}
		window, err := reader.ReadByte()
		if err != nil {
			return err
		}
		bitmapLength, err := reader.ReadByte()
		if err != nil {
			return err
		}
		remaining -= 2
		if int(window) <= lastWindow || bitmapLength == 0 || bitmapLength > 32 || int(bitmapLength) > remaining {
			return fmt.Errorf("invalid NSEC bitmap window=%d length=%d", window, bitmapLength)
		}
		bitmap := make([]byte, int(bitmapLength))
		if _, err := io.ReadFull(reader, bitmap); err != nil {
			return err
		}
		remaining -= int(bitmapLength)
		for octet, bits := range bitmap {
			for bit := 0; bit < 8; bit++ {
				if bits&(1<<uint(7-bit)) != 0 {
					r.Types = append(r.Types, DNSType(int(window)*256+octet*8+bit))
				}
			}
		}
		lastWindow = int(window)
	}
	return nil
}

func (r *DNSResourceRecordNSEC) Encode() []byte {
	var buf bytes.Buffer
	encodeDomainName(&buf, r.NextDomain, true)
	types := append([]DNSType(nil), r.Types...)
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	for i := 0; i < len(types); {
		window := int(types[i]) / 256
		end := i
		maxOctet := 0
		for end < len(types) && int(types[end])/256 == window {
			octet := (int(types[end]) % 256) / 8
			if octet > maxOctet {
				maxOctet = octet
			}
			end++
		}
		bitmap := make([]byte, maxOctet+1)
		for _, rtype := range types[i:end] {
			value := int(rtype) % 256
			bitmap[value/8] |= 1 << uint(7-value%8)
		}
		buf.WriteByte(byte(window))
		buf.WriteByte(byte(len(bitmap)))
		buf.Write(bitmap)
		i = end
	}
	return buf.Bytes()
}

func (r *DNSResourceRecordNSEC) Bytes() []byte { return r.WrapData(r.Encode()) }
