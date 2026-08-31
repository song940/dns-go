package zone

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lsongdev/dns-go/packet"
)

type Zone struct {
	Origin  string
	TTL     uint32
	Records []packet.DNSResource
}

func ParseFile(path string) (*Zone, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

func Parse(data []byte) (*Zone, error) {
	z := &Zone{
		Origin: ".",
		TTL:    3600,
	}
	text := string(data)
	lines := tokenize(text)
	if err := parseLines(z, lines); err != nil {
		return nil, err
	}
	return z, nil
}

type lineToken struct {
	text   string
	lineno int
}

func tokenize(data string) []lineToken {
	var lines []lineToken
	current := ""
	inParen := false
	lineno := 0

	for i := 0; i < len(data); i++ {
		ch := data[i]

		if ch == '\n' {
			lineno++
			if inParen {
				current += " "
				continue
			}
			trimmed := strings.TrimSpace(current)
			if trimmed != "" && !isComment(trimmed) {
				lines = append(lines, lineToken{text: trimmed, lineno: lineno})
			}
			current = ""
			continue
		}

		if ch == ';' || ch == '#' {
			for i < len(data) && data[i] != '\n' {
				i++
			}
			i--
			continue
		}

		if ch == '(' {
			inParen = true
			continue
		}
		if ch == ')' {
			inParen = false
			continue
		}

		current += string(ch)
	}

	if trimmed := strings.TrimSpace(current); trimmed != "" && !isComment(trimmed) {
		lines = append(lines, lineToken{text: trimmed, lineno: lineno})
	}

	return lines
}

func isComment(s string) bool {
	return strings.HasPrefix(s, ";") || strings.HasPrefix(s, "#")
}

func parseLines(z *Zone, lines []lineToken) error {
	currentTTL := z.TTL
	for _, line := range lines {
		fields := splitFields(line.text)
		if len(fields) == 0 {
			continue
		}

		switch {
		case strings.HasPrefix(fields[0], "$ORIGIN"):
			if len(fields) >= 2 {
				z.Origin = absDomain(fields[1])
			}
			continue
		case strings.HasPrefix(fields[0], "$TTL"):
			if len(fields) >= 2 {
				ttl, err := parseTTL(fields[1])
				if err != nil {
					return fmt.Errorf("line %d: bad $TTL: %v", line.lineno, err)
				}
				z.TTL = ttl
				currentTTL = ttl
			}
			continue
		case strings.HasPrefix(fields[0], "$INCLUDE"):
			continue
		}

		rec, newTTL, err := parseRecordLine(fields, z, currentTTL, line.lineno)
		if err != nil {
			return err
		}
		if rec != nil {
			z.Records = append(z.Records, rec)
			if newTTL != 0 {
				currentTTL = newTTL
			}
		}
	}
	return nil
}

func splitFields(s string) []string {
	var fields []string
	current := ""
	inQuote := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '"' {
			inQuote = !inQuote
			current += string(ch)
			continue
		}
		if ch == '\\' && i+1 < len(s) {
			i++
			current += string(s[i])
			continue
		}
		if (ch == ' ' || ch == '\t') && !inQuote {
			if current != "" {
				fields = append(fields, current)
				current = ""
			}
			continue
		}
		current += string(ch)
	}
	if current != "" {
		fields = append(fields, current)
	}
	return fields
}

func parseRecordLine(fields []string, z *Zone, defaultTTL uint32, lineno int) (packet.DNSResource, uint32, error) {
	if len(fields) < 2 {
		return nil, 0, fmt.Errorf("line %d: incomplete record", lineno)
	}

	idx := 0

	name := fields[idx]
	idx++

	ttl := defaultTTL
	class := packet.DNSClassIN

	if idx < len(fields) {
		if t, err := parseTTL(fields[idx]); err == nil {
			ttl = t
			idx++
		}
	}

	if idx >= len(fields) {
		return nil, 0, fmt.Errorf("line %d: missing record type", lineno)
	}
	classToken := strings.ToUpper(fields[idx])
	if classToken == "IN" || classToken == "CH" || classToken == "CS" || classToken == "HS" {
		class = classFromString(classToken)
		idx++
	}

	if idx >= len(fields) {
		return nil, 0, fmt.Errorf("line %d: missing record type", lineno)
	}

	rtype := fields[idx]
	idx++

	rdata := fields[idx:]

	dname := resolveDomain(name, z.Origin)
	rec, err := buildRecord(dname, rtype, class, ttl, rdata, lineno)
	return rec, ttl, err
}

func resolveDomain(name, origin string) string {
	if name == "@" {
		return origin
	}
	if strings.HasSuffix(name, ".") {
		return strings.TrimSuffix(name, ".")
	}
	if name == "" || name == "." {
		return origin
	}
	return name + "." + origin
}

func absDomain(s string) string {
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "."
	}
	return s
}

func buildRecord(name, rtype string, class packet.DNSClass, ttl uint32, rdata []string, lineno int) (packet.DNSResource, error) {
	switch strings.ToUpper(rtype) {
	case "A":
		return buildA(name, class, ttl, rdata, lineno)
	case "AAAA":
		return buildAAAA(name, class, ttl, rdata, lineno)
	case "CNAME":
		return buildCNAME(name, class, ttl, rdata, lineno)
	case "NS":
		return buildNS(name, class, ttl, rdata, lineno)
	case "MX":
		return buildMX(name, class, ttl, rdata, lineno)
	case "TXT":
		return buildTXT(name, class, ttl, rdata, lineno)
	case "PTR":
		return buildPTR(name, class, ttl, rdata, lineno)
	case "SOA":
		return buildSOA(name, class, ttl, rdata, lineno)
	case "SRV":
		return buildSRV(name, class, ttl, rdata, lineno)
	case "CAA":
		return buildCAA(name, class, ttl, rdata, lineno)
	case "DS":
		return buildDS(name, class, ttl, rdata, lineno)
	case "DNSKEY":
		return buildDNSKEY(name, class, ttl, rdata, lineno)
	case "RRSIG":
		return buildRRSIG(name, class, ttl, rdata, lineno)
	case "NSEC":
		return buildNSEC(name, class, ttl, rdata, lineno)
	case "TLSA":
		return buildTLSA(name, class, ttl, rdata, lineno)
	case "SVCB":
		return buildSVCB(name, class, ttl, rdata, lineno, packet.DNSTypeSVCB)
	case "HTTPS":
		return buildSVCB(name, class, ttl, rdata, lineno, packet.DNSTypeHTTPS)
	default:
		return nil, fmt.Errorf("line %d: unsupported record type %q", lineno, rtype)
	}
}

func classFromString(s string) packet.DNSClass {
	switch s {
	case "IN":
		return packet.DNSClassIN
	case "CH":
		return packet.DNSClassCH
	case "CS":
		return packet.DNSClassCS
	case "HS":
		return packet.DNSClassHS
	default:
		return packet.DNSClassIN
	}
}

func parseTTL(s string) (uint32, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return 0, fmt.Errorf("empty TTL")
	}
	if s[len(s)-1] == 'S' {
		s = s[:len(s)-1]
	}
	multiplier := uint32(1)
	switch {
	case strings.HasSuffix(s, "W"):
		multiplier = 604800
		s = s[:len(s)-1]
	case strings.HasSuffix(s, "D"):
		multiplier = 86400
		s = s[:len(s)-1]
	case strings.HasSuffix(s, "H"):
		multiplier = 3600
		s = s[:len(s)-1]
	case strings.HasSuffix(s, "M"):
		multiplier = 60
		s = s[:len(s)-1]
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("bad TTL value %q: %v", s, err)
	}
	if v > math.MaxUint32/uint64(multiplier) {
		return 0, fmt.Errorf("TTL value %q overflows uint32", s)
	}
	return uint32(v * uint64(multiplier)), nil
}

func buildA(name string, class packet.DNSClass, ttl uint32, rdata []string, lineno int) (packet.DNSResource, error) {
	if len(rdata) < 1 {
		return nil, fmt.Errorf("line %d: A record requires an IP address", lineno)
	}
	ip := net.ParseIP(rdata[0])
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("line %d: invalid A record IP %q", lineno, rdata[0])
	}
	return &packet.DNSResourceRecordA{
		DNSResourceRecord: packet.DNSResourceRecord{
			Name:  name,
			Type:  packet.DNSTypeA,
			Class: class,
			TTL:   ttl,
		},
		Address: rdata[0],
	}, nil
}

func buildAAAA(name string, class packet.DNSClass, ttl uint32, rdata []string, lineno int) (packet.DNSResource, error) {
	if len(rdata) < 1 {
		return nil, fmt.Errorf("line %d: AAAA record requires an IPv6 address", lineno)
	}
	ip := net.ParseIP(rdata[0])
	if ip == nil || ip.To16() == nil || ip.To4() != nil {
		return nil, fmt.Errorf("line %d: invalid AAAA record IP %q", lineno, rdata[0])
	}
	return &packet.DNSResourceRecordAAAA{
		DNSResourceRecord: packet.DNSResourceRecord{
			Name:  name,
			Type:  packet.DNSTypeAAAA,
			Class: class,
			TTL:   ttl,
		},
		Address: rdata[0],
	}, nil
}

func buildCNAME(name string, class packet.DNSClass, ttl uint32, rdata []string, _ int) (packet.DNSResource, error) {
	if len(rdata) < 1 {
		return nil, fmt.Errorf("CNAME record requires a target domain")
	}
	return &packet.DNSResourceRecordCNAME{
		DNSResourceRecord: packet.DNSResourceRecord{
			Name:  name,
			Type:  packet.DNSTypeCNAME,
			Class: class,
			TTL:   ttl,
		},
		Domain: rdata[0],
	}, nil
}

func buildNS(name string, class packet.DNSClass, ttl uint32, rdata []string, _ int) (packet.DNSResource, error) {
	if len(rdata) < 1 {
		return nil, fmt.Errorf("NS record requires a nameserver domain")
	}
	return &packet.DNSResourceRecordNS{
		DNSResourceRecord: packet.DNSResourceRecord{
			Name:  name,
			Type:  packet.DNSTypeNS,
			Class: class,
			TTL:   ttl,
		},
		NameServer: rdata[0],
	}, nil
}

func buildMX(name string, class packet.DNSClass, ttl uint32, rdata []string, lineno int) (packet.DNSResource, error) {
	if len(rdata) < 2 {
		return nil, fmt.Errorf("line %d: MX record requires preference and exchange", lineno)
	}
	pref, err := strconv.ParseUint(rdata[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid MX preference %q: %v", lineno, rdata[0], err)
	}
	return &packet.DNSResourceRecordMX{
		DNSResourceRecord: packet.DNSResourceRecord{
			Name:  name,
			Type:  packet.DNSTypeMX,
			Class: class,
			TTL:   ttl,
		},
		Preference: uint16(pref),
		Exchange:   rdata[1],
	}, nil
}

func buildTXT(name string, class packet.DNSClass, ttl uint32, rdata []string, _ int) (packet.DNSResource, error) {
	if len(rdata) < 1 {
		return nil, fmt.Errorf("TXT record requires text content")
	}
	content := strings.Join(rdata, " ")
	if strings.HasPrefix(content, "\"") && strings.HasSuffix(content, "\"") {
		content = content[1 : len(content)-1]
	}
	return &packet.DNSResourceRecordTXT{
		DNSResourceRecord: packet.DNSResourceRecord{
			Name:  name,
			Type:  packet.DNSTypeTXT,
			Class: class,
			TTL:   ttl,
		},
		Content: content,
	}, nil
}

func buildPTR(name string, class packet.DNSClass, ttl uint32, rdata []string, _ int) (packet.DNSResource, error) {
	if len(rdata) < 1 {
		return nil, fmt.Errorf("PTR record requires a target domain")
	}
	return &packet.DNSResourceRecordPTR{
		DNSResourceRecord: packet.DNSResourceRecord{
			Name:  name,
			Type:  packet.DNSTypePTR,
			Class: class,
			TTL:   ttl,
		},
		PtrDomainName: rdata[0],
	}, nil
}

func buildSOA(name string, class packet.DNSClass, ttl uint32, rdata []string, lineno int) (packet.DNSResource, error) {
	if len(rdata) < 7 {
		return nil, fmt.Errorf("line %d: SOA requires MNAME RNAME SERIAL REFRESH RETRY EXPIRE MINIMUM", lineno)
	}
	serial, err := strconv.ParseUint(rdata[2], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid SOA serial: %v", lineno, err)
	}
	refresh, err := strconv.ParseUint(rdata[3], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid SOA refresh: %v", lineno, err)
	}
	retry, err := strconv.ParseUint(rdata[4], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid SOA retry: %v", lineno, err)
	}
	expire, err := strconv.ParseUint(rdata[5], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid SOA expire: %v", lineno, err)
	}
	minimum, err := strconv.ParseUint(rdata[6], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid SOA minimum: %v", lineno, err)
	}
	return &packet.DNSResourceRecordSOA{
		DNSResourceRecord: packet.DNSResourceRecord{
			Name:  name,
			Type:  packet.DNSTypeSOA,
			Class: class,
			TTL:   ttl,
		},
		MName:   rdata[0],
		RName:   rdata[1],
		Serial:  uint32(serial),
		Refresh: uint32(refresh),
		Retry:   uint32(retry),
		Expire:  uint32(expire),
		Minimum: uint32(minimum),
	}, nil
}

func buildSRV(name string, class packet.DNSClass, ttl uint32, rdata []string, lineno int) (packet.DNSResource, error) {
	if len(rdata) < 4 {
		return nil, fmt.Errorf("line %d: SRV requires priority weight port target", lineno)
	}
	priority, err := strconv.ParseUint(rdata[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid SRV priority: %v", lineno, err)
	}
	weight, err := strconv.ParseUint(rdata[1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid SRV weight: %v", lineno, err)
	}
	port, err := strconv.ParseUint(rdata[2], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid SRV port: %v", lineno, err)
	}
	return &packet.DNSResourceRecordSRV{
		DNSResourceRecord: packet.DNSResourceRecord{
			Name:  name,
			Type:  packet.DNSTypeSRV,
			Class: class,
			TTL:   ttl,
		},
		Priority: uint16(priority),
		Weight:   uint16(weight),
		Port:     uint16(port),
		Target:   rdata[3],
	}, nil
}

func buildCAA(name string, class packet.DNSClass, ttl uint32, rdata []string, lineno int) (packet.DNSResource, error) {
	if len(rdata) < 3 {
		return nil, fmt.Errorf("line %d: CAA requires flags tag value", lineno)
	}
	flags, err := strconv.ParseUint(rdata[0], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid CAA flags: %v", lineno, err)
	}
	tag := trimQuotes(rdata[1])
	if tag == "" || len(tag) > 255 {
		return nil, fmt.Errorf("line %d: invalid CAA tag", lineno)
	}
	for _, ch := range tag {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) {
			return nil, fmt.Errorf("line %d: invalid CAA tag", lineno)
		}
	}
	return &packet.DNSResourceRecordCAA{
		DNSResourceRecord: packet.DNSResourceRecord{Name: name, Type: packet.DNSTypeCAA, Class: class, TTL: ttl},
		Flags:             uint8(flags), Tag: tag, Value: trimQuotes(strings.Join(rdata[2:], " ")),
	}, nil
}

func buildDS(name string, class packet.DNSClass, ttl uint32, rdata []string, lineno int) (packet.DNSResource, error) {
	if len(rdata) < 4 {
		return nil, fmt.Errorf("line %d: DS requires key-tag algorithm digest-type digest", lineno)
	}
	keyTag, err := strconv.ParseUint(rdata[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid DS key tag: %v", lineno, err)
	}
	algorithm, err := strconv.ParseUint(rdata[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid DS algorithm: %v", lineno, err)
	}
	digestType, err := strconv.ParseUint(rdata[2], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid DS digest type: %v", lineno, err)
	}
	digest, err := hex.DecodeString(strings.Join(rdata[3:], ""))
	if err != nil || len(digest) == 0 {
		return nil, fmt.Errorf("line %d: invalid DS digest", lineno)
	}
	return &packet.DNSResourceRecordDS{
		DNSResourceRecord: packet.DNSResourceRecord{Name: name, Type: packet.DNSTypeDS, Class: class, TTL: ttl},
		KeyTag:            uint16(keyTag), Algorithm: uint8(algorithm), DigestType: uint8(digestType), Digest: digest,
	}, nil
}

func buildDNSKEY(name string, class packet.DNSClass, ttl uint32, rdata []string, lineno int) (packet.DNSResource, error) {
	if len(rdata) < 4 {
		return nil, fmt.Errorf("line %d: DNSKEY requires flags protocol algorithm public-key", lineno)
	}
	flags, err := strconv.ParseUint(rdata[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid DNSKEY flags: %v", lineno, err)
	}
	protocol, err := strconv.ParseUint(rdata[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid DNSKEY protocol: %v", lineno, err)
	}
	algorithm, err := strconv.ParseUint(rdata[2], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid DNSKEY algorithm: %v", lineno, err)
	}
	publicKey, err := base64.StdEncoding.DecodeString(strings.Join(rdata[3:], ""))
	if err != nil || len(publicKey) == 0 {
		return nil, fmt.Errorf("line %d: invalid DNSKEY public key", lineno)
	}
	return &packet.DNSResourceRecordDNSKEY{
		DNSResourceRecord: packet.DNSResourceRecord{Name: name, Type: packet.DNSTypeDNSKEY, Class: class, TTL: ttl},
		Flags:             uint16(flags), Protocol: uint8(protocol), Algorithm: uint8(algorithm), PublicKey: publicKey,
	}, nil
}

func buildRRSIG(name string, class packet.DNSClass, ttl uint32, rdata []string, lineno int) (packet.DNSResource, error) {
	if len(rdata) < 9 {
		return nil, fmt.Errorf("line %d: RRSIG requires type algorithm labels original-ttl expiration inception key-tag signer signature", lineno)
	}
	typeCovered, err := dnsTypeFromString(rdata[0])
	if err != nil {
		return nil, fmt.Errorf("line %d: %v", lineno, err)
	}
	algorithm, err := strconv.ParseUint(rdata[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid RRSIG algorithm", lineno)
	}
	labels, err := strconv.ParseUint(rdata[2], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid RRSIG labels", lineno)
	}
	originalTTL, err := parseTTL(rdata[3])
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid RRSIG original TTL: %v", lineno, err)
	}
	expiration, err := parseSignatureTime(rdata[4])
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid RRSIG expiration: %v", lineno, err)
	}
	inception, err := parseSignatureTime(rdata[5])
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid RRSIG inception: %v", lineno, err)
	}
	keyTag, err := strconv.ParseUint(rdata[6], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid RRSIG key tag", lineno)
	}
	signature, err := base64.StdEncoding.DecodeString(strings.Join(rdata[8:], ""))
	if err != nil || len(signature) == 0 {
		return nil, fmt.Errorf("line %d: invalid RRSIG signature", lineno)
	}
	return &packet.DNSResourceRecordRRSIG{
		DNSResourceRecord: packet.DNSResourceRecord{Name: name, Type: packet.DNSTypeRRSIG, Class: class, TTL: ttl},
		TypeCovered:       typeCovered, Algorithm: uint8(algorithm), Labels: uint8(labels), OriginalTTL: originalTTL,
		Expiration: expiration, Inception: inception, KeyTag: uint16(keyTag), SignerName: rdata[7], Signature: signature,
	}, nil
}

func buildNSEC(name string, class packet.DNSClass, ttl uint32, rdata []string, lineno int) (packet.DNSResource, error) {
	if len(rdata) < 2 {
		return nil, fmt.Errorf("line %d: NSEC requires next-domain and at least one type", lineno)
	}
	types := make([]packet.DNSType, 0, len(rdata)-1)
	for _, value := range rdata[1:] {
		rtype, err := dnsTypeFromString(value)
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", lineno, err)
		}
		types = append(types, rtype)
	}
	return &packet.DNSResourceRecordNSEC{
		DNSResourceRecord: packet.DNSResourceRecord{Name: name, Type: packet.DNSTypeNSEC, Class: class, TTL: ttl},
		NextDomain:        rdata[0], Types: types,
	}, nil
}

func buildTLSA(name string, class packet.DNSClass, ttl uint32, rdata []string, lineno int) (packet.DNSResource, error) {
	if len(rdata) < 4 {
		return nil, fmt.Errorf("line %d: TLSA requires usage selector matching-type data", lineno)
	}
	usage, err := strconv.ParseUint(rdata[0], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid TLSA usage", lineno)
	}
	selector, err := strconv.ParseUint(rdata[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid TLSA selector", lineno)
	}
	matchingType, err := strconv.ParseUint(rdata[2], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid TLSA matching type", lineno)
	}
	data, err := hex.DecodeString(strings.Join(rdata[3:], ""))
	if err != nil || len(data) == 0 {
		return nil, fmt.Errorf("line %d: invalid TLSA certificate association data", lineno)
	}
	return &packet.DNSResourceRecordTLSA{
		DNSResourceRecord:          packet.DNSResourceRecord{Name: name, Type: packet.DNSTypeTLSA, Class: class, TTL: ttl},
		Usage:                      uint8(usage),
		Selector:                   uint8(selector),
		MatchingType:               uint8(matchingType),
		CertificateAssociationData: data,
	}, nil
}

func buildSVCB(name string, class packet.DNSClass, ttl uint32, rdata []string, lineno int, rtype packet.DNSType) (packet.DNSResource, error) {
	if len(rdata) < 2 {
		return nil, fmt.Errorf("line %d: SVCB/HTTPS requires priority and target", lineno)
	}
	priority, err := strconv.ParseUint(rdata[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("line %d: invalid SVCB priority", lineno)
	}
	params := make([]packet.SVCBParam, 0, len(rdata)-2)
	seen := make(map[uint16]bool)
	for _, field := range rdata[2:] {
		param, err := parseSVCBParam(field)
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", lineno, err)
		}
		if seen[param.Key] {
			return nil, fmt.Errorf("line %d: duplicate SVCB parameter key %d", lineno, param.Key)
		}
		seen[param.Key] = true
		params = append(params, param)
	}
	if priority == 0 && len(params) > 0 {
		return nil, fmt.Errorf("line %d: SVCB alias mode cannot contain parameters", lineno)
	}
	if seen[packet.SVCBParamKeyNoDefaultALPN] && !seen[packet.SVCBParamKeyALPN] {
		return nil, fmt.Errorf("line %d: no-default-alpn requires alpn", lineno)
	}
	for _, param := range params {
		if param.Key != packet.SVCBParamKeyMandatory {
			continue
		}
		for offset := 0; offset < len(param.Value); offset += 2 {
			required := binary.BigEndian.Uint16(param.Value[offset : offset+2])
			if !seen[required] {
				return nil, fmt.Errorf("line %d: mandatory SVCB key %d is absent", lineno, required)
			}
		}
	}
	sort.Slice(params, func(i, j int) bool { return params[i].Key < params[j].Key })
	return &packet.DNSResourceRecordSVCB{
		DNSResourceRecord: packet.DNSResourceRecord{Name: name, Type: rtype, Class: class, TTL: ttl},
		Priority:          uint16(priority), Target: rdata[1], Params: params,
	}, nil
}

func parseSVCBParam(field string) (packet.SVCBParam, error) {
	name, value, hasValue := strings.Cut(field, "=")
	key, err := svcbKey(name)
	if err != nil {
		return packet.SVCBParam{}, err
	}
	value = trimQuotes(value)
	var data []byte
	switch key {
	case packet.SVCBParamKeyMandatory:
		if !hasValue || value == "" {
			return packet.SVCBParam{}, fmt.Errorf("mandatory requires a value")
		}
		mandatoryKeys := make([]uint16, 0)
		mandatorySeen := make(map[uint16]bool)
		for _, item := range strings.Split(value, ",") {
			mandatoryKey, err := svcbKey(item)
			if err != nil || mandatoryKey == 0 || mandatorySeen[mandatoryKey] {
				return packet.SVCBParam{}, fmt.Errorf("invalid mandatory key %q", item)
			}
			mandatorySeen[mandatoryKey] = true
			mandatoryKeys = append(mandatoryKeys, mandatoryKey)
		}
		sort.Slice(mandatoryKeys, func(i, j int) bool { return mandatoryKeys[i] < mandatoryKeys[j] })
		var buf bytes.Buffer
		for _, mandatoryKey := range mandatoryKeys {
			_ = binary.Write(&buf, binary.BigEndian, mandatoryKey)
		}
		data = buf.Bytes()
	case packet.SVCBParamKeyALPN:
		if !hasValue || value == "" {
			return packet.SVCBParam{}, fmt.Errorf("alpn requires a value")
		}
		var buf bytes.Buffer
		for _, alpn := range strings.Split(value, ",") {
			if alpn == "" || len(alpn) > 255 {
				return packet.SVCBParam{}, fmt.Errorf("invalid alpn value")
			}
			buf.WriteByte(byte(len(alpn)))
			buf.WriteString(alpn)
		}
		data = buf.Bytes()
	case packet.SVCBParamKeyNoDefaultALPN:
		if hasValue && value != "" {
			return packet.SVCBParam{}, fmt.Errorf("no-default-alpn must be empty")
		}
	case packet.SVCBParamKeyPort:
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return packet.SVCBParam{}, fmt.Errorf("invalid SVCB port")
		}
		data = make([]byte, 2)
		binary.BigEndian.PutUint16(data, uint16(port))
	case packet.SVCBParamKeyIPv4Hint, packet.SVCBParamKeyIPv6Hint:
		for _, rawIP := range strings.Split(value, ",") {
			ip := net.ParseIP(rawIP)
			if key == packet.SVCBParamKeyIPv4Hint {
				ip = ip.To4()
			} else if ip != nil && ip.To4() == nil {
				ip = ip.To16()
			} else {
				ip = nil
			}
			if ip == nil {
				return packet.SVCBParam{}, fmt.Errorf("invalid IP hint %q", rawIP)
			}
			data = append(data, ip...)
		}
	case packet.SVCBParamKeyECH:
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return packet.SVCBParam{}, fmt.Errorf("invalid ech value")
		}
		data = decoded
	default:
		data = []byte(value)
	}
	return packet.SVCBParam{Key: key, Value: data}, nil
}

func svcbKey(name string) (uint16, error) {
	known := map[string]uint16{
		"mandatory": packet.SVCBParamKeyMandatory, "alpn": packet.SVCBParamKeyALPN,
		"no-default-alpn": packet.SVCBParamKeyNoDefaultALPN, "port": packet.SVCBParamKeyPort,
		"ipv4hint": packet.SVCBParamKeyIPv4Hint, "ech": packet.SVCBParamKeyECH,
		"ipv6hint": packet.SVCBParamKeyIPv6Hint, "dohpath": packet.SVCBParamKeyDoHPath,
	}
	if key, ok := known[strings.ToLower(name)]; ok {
		return key, nil
	}
	if strings.HasPrefix(strings.ToLower(name), "key") {
		value, err := strconv.ParseUint(name[3:], 10, 16)
		return uint16(value), err
	}
	return 0, fmt.Errorf("unknown SVCB parameter %q", name)
}

func dnsTypeFromString(value string) (packet.DNSType, error) {
	types := map[string]packet.DNSType{
		"A": packet.DNSTypeA, "NS": packet.DNSTypeNS, "CNAME": packet.DNSTypeCNAME,
		"SOA": packet.DNSTypeSOA, "PTR": packet.DNSTypePTR, "MX": packet.DNSTypeMX,
		"TXT": packet.DNSTypeTXT, "AAAA": packet.DNSTypeAAAA, "SRV": packet.DNSTypeSRV,
		"DS": packet.DNSTypeDS, "RRSIG": packet.DNSTypeRRSIG, "NSEC": packet.DNSTypeNSEC,
		"DNSKEY": packet.DNSTypeDNSKEY, "TLSA": packet.DNSTypeTLSA, "SVCB": packet.DNSTypeSVCB,
		"HTTPS": packet.DNSTypeHTTPS, "CAA": packet.DNSTypeCAA,
	}
	upper := strings.ToUpper(value)
	if rtype, ok := types[upper]; ok {
		return rtype, nil
	}
	if strings.HasPrefix(upper, "TYPE") {
		numeric, err := strconv.ParseUint(upper[4:], 10, 16)
		if err == nil {
			return packet.DNSType(numeric), nil
		}
	}
	return 0, fmt.Errorf("unknown DNS type %q", value)
}

func parseSignatureTime(value string) (uint32, error) {
	if len(value) == 14 {
		parsed, err := time.Parse("20060102150405", value)
		if err != nil {
			return 0, err
		}
		unix := parsed.Unix()
		if unix < 0 || unix > math.MaxUint32 {
			return 0, fmt.Errorf("signature time out of range")
		}
		return uint32(unix), nil
	}
	numeric, err := strconv.ParseUint(value, 10, 32)
	return uint32(numeric), err
}

func trimQuotes(value string) string {
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		return value[1 : len(value)-1]
	}
	return value
}
