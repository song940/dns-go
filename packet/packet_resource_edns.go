package packet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// EDNS Option Codes
const (
	EDNSOptionLLQ          uint16 = 1
	EDNSOptionUL           uint16 = 2
	EDNSOptionNSID         uint16 = 3
	EDNSOptionDAU          uint16 = 5
	EDNSOptionDHU          uint16 = 6
	EDNSOptionN3U          uint16 = 7
	EDNSOptionClientSubnet uint16 = 8
	EDNSOptionExpire       uint16 = 9
	EDNSOptionCookie       uint16 = 10
	EDNSOptionTCPKeepalive uint16 = 11
	EDNSOptionPadding      uint16 = 12
	EDNSOptionChain        uint16 = 13
	EDNSOptionKeyTag       uint16 = 14
	EDNSOptionDeviceID     uint16 = 26
)

type DNSResourceRecordEDNS struct {
	DNSResourceRecord

	UDPSize  uint16
	ExtRCode uint8
	Version  uint8
	Flags    uint16
	Options  []EDNSOption
}

type EDNSOption struct {
	Code uint16
	Data []byte
}

// Decode implements DNSResource.
func (d *DNSResourceRecordEDNS) Decode(reader *bytes.Reader, length uint16) error {
	d.UDPSize = uint16(d.Class)
	d.ExtRCode = uint8(d.TTL >> 24)
	d.Version = uint8((d.TTL >> 16) & 0xFF)
	d.Flags = uint16(d.TTL & 0xFFFF)

	remaining := int(length)
	for remaining > 0 {
		if remaining < 4 {
			return fmt.Errorf("EDNS option header truncated: %d bytes remain", remaining)
		}
		var option EDNSOption
		if err := binary.Read(reader, binary.BigEndian, &option.Code); err != nil {
			return err
		}
		var optionLength uint16
		if err := binary.Read(reader, binary.BigEndian, &optionLength); err != nil {
			return err
		}
		remaining -= 4
		if int(optionLength) > remaining {
			return fmt.Errorf("EDNS option length %d exceeds remaining RDATA %d", optionLength, remaining)
		}
		option.Data = make([]byte, optionLength)
		if _, err := io.ReadFull(reader, option.Data); err != nil {
			return err
		}
		remaining -= int(optionLength)
		d.Options = append(d.Options, option)
	}
	return nil
}

// Encode implements DNSResource.
// For EDNS, the RDATA only contains options.
// UDPSize, ExtRCode, Version, and Flags are encoded in the RR header (Class and TTL fields).
func (d *DNSResourceRecordEDNS) Encode() []byte {
	var buf bytes.Buffer

	for _, option := range d.Options {
		binary.Write(&buf, binary.BigEndian, option.Code)
		binary.Write(&buf, binary.BigEndian, uint16(len(option.Data)))
		buf.Write(option.Data)
	}

	return buf.Bytes()
}

func (r *DNSResourceRecordEDNS) Bytes() []byte {
	r.syncTTL()
	return r.WrapData(r.Encode())
}

// AddEDNSOption adds an EDNS option to the EDNS record.
func (d *DNSResourceRecordEDNS) AddEDNSOption(code uint16, data []byte) {
	d.Options = append(d.Options, EDNSOption{
		Code: code,
		Data: data,
	})
}

// syncTTL updates the TTL field from ExtRCode, Version, and Flags.
func (d *DNSResourceRecordEDNS) syncTTL() {
	d.TTL = (uint32(d.ExtRCode) << 24) | (uint32(d.Version) << 16) | uint32(d.Flags)
}

// AddEDNSOptionClientSubnet adds an EDNS Client Subnet option (RFC 7871).
// address is the client IP address, and prefixLength is the subnet mask length.
func (d *DNSResourceRecordEDNS) AddEDNSOptionClientSubnet(address net.IP, prefixLength uint8) {
	family := uint16(1) // IPv4
	if address.To4() == nil {
		family = 2 // IPv6
	}

	// Determine address length based on family
	addrLen := 4
	if family == 2 {
		addrLen = 8 // Use first 8 bytes for IPv6
	}

	// Truncate address to prefix length
	var truncatedIP net.IP
	if family == 1 {
		truncatedIP = address.To4()
	} else {
		truncatedIP = address.To16()
	}
	// Calculate bytes needed based on prefix length
	bytesNeeded := (int(prefixLength) + 7) / 8
	if bytesNeeded > addrLen {
		bytesNeeded = addrLen
	}
	truncatedIP = truncatedIP[:bytesNeeded]

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, family)
	buf.WriteByte(24) // Source netmask length (for IPv4)
	if family == 2 {
		buf.WriteByte(prefixLength) // For IPv6
	}
	buf.WriteByte(0) // Scope netmask length

	buf.Write(truncatedIP)

	d.AddEDNSOption(EDNSOptionClientSubnet, buf.Bytes())
}

// AddEDNSOptionCookie adds an EDNS Cookie option (RFC 7873).
// clientCookie should be 8 bytes, serverCookie should be 8-32 bytes (or empty for client)
func (d *DNSResourceRecordEDNS) AddEDNSOptionCookie(clientCookie []byte, serverCookie []byte) {
	var buf bytes.Buffer
	buf.Write(clientCookie)
	buf.Write(serverCookie)
	d.AddEDNSOption(EDNSOptionCookie, buf.Bytes())
}

// AddEDNSOptionPadding adds an EDNS Padding option (RFC 7830).
func (d *DNSResourceRecordEDNS) AddEDNSOptionPadding(size int) {
	d.AddEDNSOption(EDNSOptionPadding, make([]byte, size))
}

// SetDNSSECOK sets the DNSSEC OK (DO) flag.
func (d *DNSResourceRecordEDNS) SetDNSSECOK(do bool) {
	if do {
		d.Flags |= 0x8000
	} else {
		d.Flags &^= 0x8000
	}
	// Update TTL to include the flags
	d.TTL = (uint32(d.ExtRCode) << 24) | (uint32(d.Version) << 16) | uint32(d.Flags)
}

// GetDNSSECOK returns the DNSSEC OK (DO) flag status.
func (d *DNSResourceRecordEDNS) GetDNSSECOK() bool {
	return (d.Flags & 0x8000) != 0
}

// NewEDNSRecord creates a new EDNS0 OPT record with default values.
// udpSize is the maximum UDP payload size (typically 4096).
func NewEDNSRecord(udpSize uint16) *DNSResourceRecordEDNS {
	return &DNSResourceRecordEDNS{
		DNSResourceRecord: DNSResourceRecord{
			Name:  ".",
			Type:  DNSTypeEDNS,
			Class: DNSClass(udpSize),
			TTL:   0,
		},
		UDPSize:  udpSize,
		ExtRCode: 0,
		Version:  0,
		Flags:    0,
		Options:  nil,
	}
}
