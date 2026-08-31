package packet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// Assuming DNSType and DNSClass are defined elsewhere.
type DNSQuestion struct {
	Name  string
	Type  DNSType
	Class DNSClass
}

func (q *DNSQuestion) Parse(reader *bytes.Reader) error {
	// Decode domain name
	name, err := decodeDomainName(reader)
	if err != nil {
		return err
	}
	q.Name = name
	// Decode type
	typeBytes := make([]byte, 2)
	if _, err := reader.Read(typeBytes); err != nil {
		return err
	}
	q.Type = DNSType(binary.BigEndian.Uint16(typeBytes))
	// Decode class
	classBytes := make([]byte, 2)
	if _, err := reader.Read(classBytes); err != nil {
		return err
	}
	q.Class = DNSClass(binary.BigEndian.Uint16(classBytes))
	return nil
}

func (q *DNSQuestion) Bytes() []byte {
	var buf bytes.Buffer
	// Encode domain name
	encodeDomainName(&buf, q.Name, true)
	// Encode type
	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, uint16(q.Type))
	buf.Write(typeBytes)
	// Encode class
	classBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(classBytes, uint16(q.Class))
	buf.Write(classBytes)
	return buf.Bytes()
}

func encodeDomainName(buf *bytes.Buffer, domain string, addNullTerminator bool) {
	domain = strings.TrimRight(domain, ".")
	// Handle root domain specially
	if domain == "." || domain == "" {
		if addNullTerminator {
			buf.WriteByte(0x00)
		}
		return
	}

	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if label == "" {
			continue
		}
		// Write label length
		buf.WriteByte(byte(len(label)))
		// Write label content
		buf.WriteString(label)
	}
	if addNullTerminator {
		buf.WriteByte(0x00)
	}
}

func decodeDomainName(reader *bytes.Reader) (name string, err error) {
	return decodeDomainNameInternal(reader, make(map[int64]bool), 0)
}

func decodeDomainNameInternal(reader *bytes.Reader, visited map[int64]bool, depth int) (name string, err error) {
	if depth > 128 {
		return "", fmt.Errorf("DNS compression pointer depth exceeded")
	}
	var parts []string
	for {
		labelOffset, err := reader.Seek(0, io.SeekCurrent)
		if err != nil {
			return "", fmt.Errorf("error reading label offset: %v", err)
		}
		labelLen, err := reader.ReadByte()
		if err != nil {
			return "", fmt.Errorf("error reading label length: %v", err)
		}
		if labelLen == 0 {
			break
		}
		if labelLen&0xc0 == 0xc0 {
			pointerByte, err := reader.ReadByte()
			if err != nil {
				return "", fmt.Errorf("error reading pointer byte: %v", err)
			}
			pointer := int64((uint16(labelLen&0x3f) << 8) | uint16(pointerByte))
			if pointer >= labelOffset || pointer >= reader.Size() {
				return "", fmt.Errorf("invalid DNS compression pointer %d at offset %d", pointer, labelOffset)
			}
			if visited[pointer] {
				return "", fmt.Errorf("DNS compression pointer loop at offset %d", pointer)
			}
			visited[pointer] = true
			returnOffset, _ := reader.Seek(0, io.SeekCurrent)
			if _, err := reader.Seek(pointer, io.SeekStart); err != nil {
				return "", fmt.Errorf("error seeking to pointer position: %v", err)
			}
			part, decodeErr := decodeDomainNameInternal(reader, visited, depth+1)
			_, restoreErr := reader.Seek(returnOffset, io.SeekStart)
			if decodeErr != nil {
				return "", decodeErr
			}
			if restoreErr != nil {
				return "", fmt.Errorf("error restoring reader position: %v", restoreErr)
			}
			if part != "." {
				parts = append(parts, part)
			}
			break
		}
		if labelLen&0xc0 != 0 {
			return "", fmt.Errorf("invalid DNS label length byte %#x", labelLen)
		}

		labelBytes := make([]byte, labelLen)
		if _, err := io.ReadFull(reader, labelBytes); err != nil {
			return "", fmt.Errorf("error reading label: %v", err)
		}
		parts = append(parts, string(labelBytes))
	}

	if len(parts) == 0 {
		return ".", nil // Root domain (used in EDNS OPT records)
	}

	name = strings.Join(parts, ".")
	if len(name) > 253 {
		return "", fmt.Errorf("decoded domain name exceeds 253 bytes")
	}
	return
}
