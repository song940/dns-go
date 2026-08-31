package packet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
)

const (
	SVCBParamKeyMandatory     uint16 = 0
	SVCBParamKeyALPN          uint16 = 1
	SVCBParamKeyNoDefaultALPN uint16 = 2
	SVCBParamKeyPort          uint16 = 3
	SVCBParamKeyIPv4Hint      uint16 = 4
	SVCBParamKeyECH           uint16 = 5
	SVCBParamKeyIPv6Hint      uint16 = 6
	SVCBParamKeyDoHPath       uint16 = 7
)

type SVCBParam struct {
	Key   uint16
	Value []byte
}

type DNSResourceRecordSVCB struct {
	DNSResourceRecord
	Priority uint16
	Target   string
	Params   []SVCBParam
}

func (r *DNSResourceRecordSVCB) Decode(reader *bytes.Reader, length uint16) (err error) {
	if length < 3 {
		return fmt.Errorf("SVCB RDATA is too short: %d", length)
	}
	start := reader.Len()
	if err = binary.Read(reader, binary.BigEndian, &r.Priority); err != nil {
		return err
	}
	if r.Target, err = decodeDomainName(reader); err != nil {
		return err
	}
	remaining := int(length) - (start - reader.Len())
	lastKey := -1
	for remaining > 0 {
		if remaining < 4 {
			return fmt.Errorf("SVCB parameter header is truncated")
		}
		var key, valueLength uint16
		if err = binary.Read(reader, binary.BigEndian, &key); err != nil {
			return err
		}
		if err = binary.Read(reader, binary.BigEndian, &valueLength); err != nil {
			return err
		}
		remaining -= 4
		if int(key) <= lastKey || int(valueLength) > remaining {
			return fmt.Errorf("invalid SVCB parameter key=%d length=%d", key, valueLength)
		}
		value := make([]byte, int(valueLength))
		if _, err = io.ReadFull(reader, value); err != nil {
			return err
		}
		remaining -= int(valueLength)
		r.Params = append(r.Params, SVCBParam{Key: key, Value: value})
		lastKey = int(key)
	}
	return validateSVCBParams(r.Priority, r.Params)
}

func validateSVCBParams(priority uint16, params []SVCBParam) error {
	if priority == 0 && len(params) != 0 {
		return fmt.Errorf("SVCB alias mode cannot contain parameters")
	}
	present := make(map[uint16]bool, len(params))
	for _, param := range params {
		present[param.Key] = true
		switch param.Key {
		case SVCBParamKeyALPN: // one or more non-empty character strings
			for offset := 0; offset < len(param.Value); {
				segmentLength := int(param.Value[offset])
				offset++
				if segmentLength == 0 || segmentLength > len(param.Value)-offset {
					return fmt.Errorf("invalid SVCB alpn value")
				}
				offset += segmentLength
			}
			if len(param.Value) == 0 {
				return fmt.Errorf("invalid empty SVCB alpn value")
			}
		case SVCBParamKeyNoDefaultALPN:
			if len(param.Value) != 0 {
				return fmt.Errorf("SVCB no-default-alpn value must be empty")
			}
		case SVCBParamKeyPort:
			if len(param.Value) != 2 {
				return fmt.Errorf("SVCB port value must be 2 bytes")
			}
		case SVCBParamKeyIPv4Hint:
			if len(param.Value) == 0 || len(param.Value)%4 != 0 {
				return fmt.Errorf("invalid SVCB ipv4hint length %d", len(param.Value))
			}
		case SVCBParamKeyIPv6Hint:
			if len(param.Value) == 0 || len(param.Value)%16 != 0 {
				return fmt.Errorf("invalid SVCB ipv6hint length %d", len(param.Value))
			}
		}
	}
	if present[SVCBParamKeyNoDefaultALPN] && !present[SVCBParamKeyALPN] {
		return fmt.Errorf("SVCB no-default-alpn requires alpn")
	}
	for _, param := range params {
		if param.Key != SVCBParamKeyMandatory {
			continue
		}
		if len(param.Value) == 0 || len(param.Value)%2 != 0 {
			return fmt.Errorf("invalid SVCB mandatory value length %d", len(param.Value))
		}
		lastKey := -1
		for offset := 0; offset < len(param.Value); offset += 2 {
			key := binary.BigEndian.Uint16(param.Value[offset : offset+2])
			if key == 0 || int(key) <= lastKey || !present[key] {
				return fmt.Errorf("invalid or absent mandatory SVCB key %d", key)
			}
			lastKey = int(key)
		}
	}
	return nil
}

func (r *DNSResourceRecordSVCB) Encode() []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, r.Priority)
	encodeDomainName(&buf, r.Target, true)
	params := append([]SVCBParam(nil), r.Params...)
	sort.Slice(params, func(i, j int) bool { return params[i].Key < params[j].Key })
	for _, param := range params {
		_ = binary.Write(&buf, binary.BigEndian, param.Key)
		_ = binary.Write(&buf, binary.BigEndian, uint16(len(param.Value)))
		buf.Write(param.Value)
	}
	return buf.Bytes()
}

func (r *DNSResourceRecordSVCB) Bytes() []byte { return r.WrapData(r.Encode()) }
