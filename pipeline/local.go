package pipeline

import (
	"fmt"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/packet"
	"github.com/lsongdev/dns-go/zone"
)

// LocalSource resolves a query against an authoritative snapshot. InZone must
// be true for both positive and negative authoritative answers.
type LocalSource interface {
	Resolve(qname string, qtype packet.DNSType) LocalResult
}

type LocalResult struct {
	InZone        bool
	Authoritative bool
	RCode         uint8
	Answers       []packet.DNSResource
	Authorities   []packet.DNSResource
	Additionals   []packet.DNSResource
}

// ZoneData is the storage-neutral input used to compile a snapshot. SaaS
// control planes can build it from a database or API without using YAML.
type ZoneData struct {
	Origin  string
	Records []packet.DNSResource
}

// LocalIndex stores an immutable compiled snapshot. Replace builds a complete
// new index and atomically publishes it, so queries never observe a partial
// zone update and never take a write lock.
type LocalIndex struct {
	snapshot atomic.Pointer[localSnapshot]
}

type localSnapshot struct {
	root  *zoneTrieNode
	zones []*indexedZone
}

type zoneTrieNode struct {
	children map[string]*zoneTrieNode
	zone     *indexedZone
}

type indexedZone struct {
	origin string
	owners map[string]map[packet.DNSType][]packet.DNSResource
	names  map[string]struct{}
	soa    []packet.DNSResource
}

func NewLocalIndex(domains []config.DomainSpec) (*LocalIndex, error) {
	li := &LocalIndex{}
	if err := li.Replace(domains); err != nil {
		return nil, err
	}
	return li, nil
}

func NewLocalIndexFromZones(zones []ZoneData) (*LocalIndex, error) {
	li := &LocalIndex{}
	if err := li.ReplaceZones(zones); err != nil {
		return nil, err
	}
	return li, nil
}

// Replace compiles and atomically publishes a complete set of zones.
func (li *LocalIndex) Replace(domains []config.DomainSpec) error {
	zones, err := loadConfiguredZones(domains)
	if err != nil {
		return err
	}
	return li.ReplaceZones(zones)
}

// ReplaceZones is the storage-neutral hot-update API. Compilation happens
// before Store, so an error leaves the current snapshot untouched.
func (li *LocalIndex) ReplaceZones(zones []ZoneData) error {
	snapshot, err := compileLocalSnapshot(zones)
	if err != nil {
		return err
	}
	li.snapshot.Store(snapshot)
	return nil
}

func loadConfiguredZones(domains []config.DomainSpec) ([]ZoneData, error) {
	zones := make([]ZoneData, 0, len(domains))
	for i, d := range domains {
		if d.Domain == "" {
			return nil, fmt.Errorf("domains[%d]: domain required", i)
		}
		origin := canonicalName(d.Domain)
		if origin == "" {
			return nil, fmt.Errorf("domains[%d]: invalid root domain", i)
		}
		var z *zone.Zone
		var err error
		switch {
		case d.ZoneFile != "" && len(d.Records) > 0:
			return nil, fmt.Errorf("domains[%d] (%s): only one of records or zone_file allowed", i, d.Domain)
		case d.ZoneFile != "":
			z, err = zone.ParseFile(d.ZoneFile)
		default:
			z, err = parseInline(origin, d.Records)
		}
		if err != nil {
			return nil, fmt.Errorf("domains[%d] (%s): %w", i, d.Domain, err)
		}
		zones = append(zones, ZoneData{Origin: origin, Records: z.Records})
	}
	return zones, nil
}

func compileLocalSnapshot(zones []ZoneData) (*localSnapshot, error) {
	root := &zoneTrieNode{children: make(map[string]*zoneTrieNode)}
	seen := make(map[string]bool)
	for i, data := range zones {
		origin := canonicalName(data.Origin)
		if origin == "" {
			return nil, fmt.Errorf("zones[%d]: origin required", i)
		}
		if seen[origin] {
			return nil, fmt.Errorf("zones[%d] (%s): duplicate zone", i, data.Origin)
		}
		seen[origin] = true
		indexed, err := indexZone(origin, data.Records)
		if err != nil {
			return nil, fmt.Errorf("zones[%d] (%s): %w", i, data.Origin, err)
		}
		insertZone(root, indexed)
	}
	compiled := make([]*indexedZone, 0, len(zones))
	// Rewalk the input to preserve deterministic validation order.
	for _, data := range zones {
		if z := matchIndexedZone(root, canonicalName(data.Origin)); z != nil {
			compiled = append(compiled, z)
		}
	}
	return &localSnapshot{root: root, zones: compiled}, nil
}

// ValidateAuthoritative enforces the minimum apex data required by a public
// authoritative server. Hybrid/local override use may intentionally omit it.
func (li *LocalIndex) ValidateAuthoritative() error {
	snapshot := li.snapshot.Load()
	if snapshot == nil || len(snapshot.zones) == 0 {
		return fmt.Errorf("authoritative snapshot has no zones")
	}
	for _, z := range snapshot.zones {
		apex := z.owners[z.origin]
		if len(apex[packet.DNSTypeSOA]) != 1 {
			return fmt.Errorf("zone %q requires exactly one apex SOA", z.origin)
		}
		if len(apex[packet.DNSTypeNS]) == 0 {
			return fmt.Errorf("zone %q requires at least one apex NS", z.origin)
		}
	}
	return nil
}

func parseInline(origin string, records []string) (*zone.Zone, error) {
	if len(records) == 0 {
		return &zone.Zone{Origin: origin}, nil
	}
	var b strings.Builder
	b.WriteString("$ORIGIN ")
	b.WriteString(origin)
	b.WriteString(".\n")
	for _, line := range records {
		b.WriteString(line)
		b.WriteString("\n")
	}
	return zone.Parse([]byte(b.String()))
}

func (li *LocalIndex) Lookup(qname string, qtype packet.DNSType) []packet.DNSResource {
	return li.Resolve(qname, qtype).Answers
}

func (li *LocalIndex) Resolve(qname string, qtype packet.DNSType) LocalResult {
	qname = canonicalName(qname)
	snapshot := li.snapshot.Load()
	if snapshot == nil {
		return LocalResult{}
	}
	z := matchIndexedZone(snapshot.root, qname)
	if z == nil {
		return LocalResult{}
	}

	if cut, ns := z.findDelegation(qname); cut != "" && !(qname == cut && qtype == packet.DNSTypeDS) {
		return LocalResult{
			InZone:        true,
			Authoritative: false,
			RCode:         rcodeNoError,
			Authorities:   ns,
			Additionals:   z.glueFor(ns),
		}
	}

	result := LocalResult{InZone: true, Authoritative: true, RCode: rcodeNoError}
	owner, exists := z.owners[qname]
	if exists {
		result.Answers = z.answerOwner(qname, owner, qtype)
		if len(result.Answers) == 0 {
			result.Authorities = z.soa
		}
		return result
	}
	if _, exists := z.names[qname]; exists {
		result.Authorities = z.soa
		return result
	}

	wildcard := z.findWildcard(qname)
	if wildcard != nil {
		result.Answers = z.answerWildcard(qname, wildcard, qtype)
		if len(result.Answers) == 0 {
			result.Authorities = z.soa
		}
		return result
	}

	result.RCode = rcodeNXDOMAIN
	result.Authorities = z.soa
	return result
}

func indexZone(origin string, records []packet.DNSResource) (*indexedZone, error) {
	z := &indexedZone{
		origin: origin,
		owners: make(map[string]map[packet.DNSType][]packet.DNSResource),
		names:  map[string]struct{}{origin: {}},
	}
	for _, record := range records {
		name := canonicalName(recordName(record))
		if name == "" {
			continue
		}
		if name != origin && !strings.HasSuffix(name, "."+origin) {
			return nil, fmt.Errorf("record owner %q is outside zone %q", name, origin)
		}
		if record.GetType() == packet.DNSTypeEDNS {
			return nil, fmt.Errorf("OPT record is not valid zone data")
		}
		record = cloneResourceWithName(record, name)
		if z.owners[name] == nil {
			z.owners[name] = make(map[packet.DNSType][]packet.DNSResource)
		}
		z.owners[name][record.GetType()] = append(z.owners[name][record.GetType()], record)
		if record.GetType() == packet.DNSTypeSOA && name == origin {
			z.soa = append(z.soa, record)
		}
		z.addNameAndAncestors(name)
	}
	for name, owner := range z.owners {
		cnames := owner[packet.DNSTypeCNAME]
		if len(cnames) > 1 {
			return nil, fmt.Errorf("owner %q has multiple CNAME records", name)
		}
		if len(cnames) == 1 && len(owner) > 1 {
			return nil, fmt.Errorf("owner %q has CNAME and other record types", name)
		}
		if len(cnames) == 1 && name == origin {
			return nil, fmt.Errorf("zone apex %q cannot be a CNAME", name)
		}
		if soa := owner[packet.DNSTypeSOA]; len(soa) > 0 {
			if name != origin {
				return nil, fmt.Errorf("SOA owner %q must be the zone apex", name)
			}
			if len(soa) > 1 {
				return nil, fmt.Errorf("zone %q has multiple SOA records", origin)
			}
		}
	}
	if err := z.validateCNAMECycles(); err != nil {
		return nil, err
	}
	return z, nil
}

func (z *indexedZone) validateCNAMECycles() error {
	for start, owner := range z.owners {
		if len(owner[packet.DNSTypeCNAME]) == 0 {
			continue
		}
		seen := map[string]bool{start: true}
		current := start
		for {
			cnames := z.owners[current][packet.DNSTypeCNAME]
			if len(cnames) == 0 {
				break
			}
			cname, ok := cnames[0].(*packet.DNSResourceRecordCNAME)
			if !ok {
				return fmt.Errorf("owner %q has invalid CNAME record implementation", current)
			}
			target := z.resolveTarget(cname.Domain)
			if seen[target] {
				return fmt.Errorf("CNAME cycle involving %q", target)
			}
			seen[target] = true
			current = target
		}
	}
	return nil
}

func (z *indexedZone) addNameAndAncestors(name string) {
	for current := name; current != ""; current = parentName(current) {
		z.names[current] = struct{}{}
		if current == z.origin {
			return
		}
	}
}

func insertZone(root *zoneTrieNode, z *indexedZone) {
	node := root
	labels := strings.Split(z.origin, ".")
	for i := len(labels) - 1; i >= 0; i-- {
		label := labels[i]
		if node.children[label] == nil {
			node.children[label] = &zoneTrieNode{children: make(map[string]*zoneTrieNode)}
		}
		node = node.children[label]
	}
	node.zone = z
}

func matchIndexedZone(root *zoneTrieNode, name string) *indexedZone {
	node := root
	var best *indexedZone
	labels := strings.Split(name, ".")
	for i := len(labels) - 1; i >= 0; i-- {
		node = node.children[labels[i]]
		if node == nil {
			break
		}
		if node.zone != nil {
			best = node.zone
		}
	}
	return best
}

func (z *indexedZone) answerOwner(name string, owner map[packet.DNSType][]packet.DNSResource, qtype packet.DNSType) []packet.DNSResource {
	if qtype == packet.DNSTypeAny {
		types := make([]int, 0, len(owner))
		for rtype := range owner {
			types = append(types, int(rtype))
		}
		sort.Ints(types)
		var out []packet.DNSResource
		for _, value := range types {
			out = append(out, owner[packet.DNSType(value)]...)
		}
		return out
	}
	if records := owner[qtype]; len(records) > 0 {
		return records
	}
	if qtype != packet.DNSTypeCNAME {
		if cnames := owner[packet.DNSTypeCNAME]; len(cnames) > 0 {
			return z.followCNAME(cnames, qtype)
		}
	}
	return nil
}

func (z *indexedZone) followCNAME(cnames []packet.DNSResource, qtype packet.DNSType) []packet.DNSResource {
	out := append([]packet.DNSResource(nil), cnames...)
	visited := make(map[string]bool)
	for depth := 0; depth < 8 && len(cnames) > 0; depth++ {
		cname, ok := cnames[0].(*packet.DNSResourceRecordCNAME)
		if !ok {
			break
		}
		target := z.resolveTarget(cname.Domain)
		if visited[target] {
			break
		}
		visited[target] = true
		owner := z.owners[target]
		if owner == nil {
			break
		}
		if records := owner[qtype]; len(records) > 0 {
			out = append(out, records...)
			break
		}
		cnames = owner[packet.DNSTypeCNAME]
		out = append(out, cnames...)
	}
	return out
}

func (z *indexedZone) resolveTarget(target string) string {
	if strings.HasSuffix(target, ".") {
		return canonicalName(target)
	}
	canonical := canonicalName(target)
	// ZoneData uses canonical FQDNs without requiring a presentation-format
	// trailing dot. A single label retains traditional zone-file relativity.
	if strings.Contains(canonical, ".") {
		return canonical
	}
	return canonicalName(target + "." + z.origin)
}

func (z *indexedZone) findWildcard(name string) map[packet.DNSType][]packet.DNSResource {
	for candidate := parentName(name); candidate != ""; candidate = parentName(candidate) {
		if _, exists := z.names[candidate]; exists {
			return z.owners["*."+candidate]
		}
		if candidate == z.origin {
			break
		}
	}
	return nil
}

func (z *indexedZone) answerWildcard(qname string, owner map[packet.DNSType][]packet.DNSResource, qtype packet.DNSType) []packet.DNSResource {
	if qtype == packet.DNSTypeAny {
		records := z.answerOwner(qname, owner, qtype)
		out := make([]packet.DNSResource, 0, len(records))
		for _, record := range records {
			out = append(out, cloneResourceWithName(record, qname))
		}
		return out
	}
	if records := owner[qtype]; len(records) > 0 {
		out := make([]packet.DNSResource, 0, len(records))
		for _, record := range records {
			out = append(out, cloneResourceWithName(record, qname))
		}
		return out
	}
	if qtype != packet.DNSTypeCNAME {
		cnames := owner[packet.DNSTypeCNAME]
		if len(cnames) > 0 {
			out := make([]packet.DNSResource, 0, len(cnames)+1)
			for _, record := range cnames {
				out = append(out, cloneResourceWithName(record, qname))
			}
			chained := z.followCNAME(cnames, qtype)
			if len(chained) > len(cnames) {
				out = append(out, chained[len(cnames):]...)
			}
			return out
		}
	}
	return nil
}

func (z *indexedZone) findDelegation(name string) (string, []packet.DNSResource) {
	for current := name; current != "" && current != z.origin; current = parentName(current) {
		if ns := z.owners[current][packet.DNSTypeNS]; len(ns) > 0 {
			return current, ns
		}
	}
	return "", nil
}

func (z *indexedZone) glueFor(ns []packet.DNSResource) []packet.DNSResource {
	var glue []packet.DNSResource
	for _, record := range ns {
		nsRecord, ok := record.(*packet.DNSResourceRecordNS)
		if !ok {
			continue
		}
		target := z.resolveTarget(nsRecord.NameServer)
		if target != z.origin && !strings.HasSuffix(target, "."+z.origin) {
			continue
		}
		for _, rtype := range []packet.DNSType{packet.DNSTypeA, packet.DNSTypeAAAA} {
			glue = append(glue, z.owners[target][rtype]...)
		}
	}
	return glue
}

func canonicalName(name string) string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(name), "."))
}

func parentName(name string) string {
	if dot := strings.IndexByte(name, '.'); dot >= 0 {
		return name[dot+1:]
	}
	return ""
}

func cloneResourceWithName(record packet.DNSResource, name string) packet.DNSResource {
	switch x := record.(type) {
	case *packet.DNSResourceRecordA:
		clone := *x
		clone.Name = name
		return &clone
	case *packet.DNSResourceRecordAAAA:
		clone := *x
		clone.Name = name
		return &clone
	case *packet.DNSResourceRecordCNAME:
		clone := *x
		clone.Name = name
		return &clone
	case *packet.DNSResourceRecordMX:
		clone := *x
		clone.Name = name
		return &clone
	case *packet.DNSResourceRecordNS:
		clone := *x
		clone.Name = name
		return &clone
	case *packet.DNSResourceRecordTXT:
		clone := *x
		clone.Name = name
		return &clone
	case *packet.DNSResourceRecordPTR:
		clone := *x
		clone.Name = name
		return &clone
	case *packet.DNSResourceRecordSOA:
		clone := *x
		clone.Name = name
		return &clone
	case *packet.DNSResourceRecordSRV:
		clone := *x
		clone.Name = name
		return &clone
	case *packet.DNSResourceRecordCAA:
		clone := *x
		clone.Name = name
		return &clone
	case *packet.DNSResourceRecordDS:
		clone := *x
		clone.Name = name
		clone.Digest = append([]byte(nil), x.Digest...)
		return &clone
	case *packet.DNSResourceRecordDNSKEY:
		clone := *x
		clone.Name = name
		clone.PublicKey = append([]byte(nil), x.PublicKey...)
		return &clone
	case *packet.DNSResourceRecordRRSIG:
		clone := *x
		clone.Name = name
		clone.Signature = append([]byte(nil), x.Signature...)
		return &clone
	case *packet.DNSResourceRecordNSEC:
		clone := *x
		clone.Name = name
		clone.Types = append([]packet.DNSType(nil), x.Types...)
		return &clone
	case *packet.DNSResourceRecordTLSA:
		clone := *x
		clone.Name = name
		clone.CertificateAssociationData = append([]byte(nil), x.CertificateAssociationData...)
		return &clone
	case *packet.DNSResourceRecordSVCB:
		clone := *x
		clone.Name = name
		clone.Params = make([]packet.SVCBParam, len(x.Params))
		for i, param := range x.Params {
			clone.Params[i] = packet.SVCBParam{Key: param.Key, Value: append([]byte(nil), param.Value...)}
		}
		return &clone
	case *packet.DNSResourceRecordUnknown:
		clone := *x
		clone.Name = name
		clone.RData = append([]byte(nil), x.RData...)
		return &clone
	default:
		return record
	}
}

func recordName(r packet.DNSResource) string {
	switch x := r.(type) {
	case *packet.DNSResourceRecordA:
		return x.Name
	case *packet.DNSResourceRecordAAAA:
		return x.Name
	case *packet.DNSResourceRecordCNAME:
		return x.Name
	case *packet.DNSResourceRecordMX:
		return x.Name
	case *packet.DNSResourceRecordNS:
		return x.Name
	case *packet.DNSResourceRecordTXT:
		return x.Name
	case *packet.DNSResourceRecordPTR:
		return x.Name
	case *packet.DNSResourceRecordSOA:
		return x.Name
	case *packet.DNSResourceRecordSRV:
		return x.Name
	case *packet.DNSResourceRecordCAA:
		return x.Name
	case *packet.DNSResourceRecordDS:
		return x.Name
	case *packet.DNSResourceRecordDNSKEY:
		return x.Name
	case *packet.DNSResourceRecordRRSIG:
		return x.Name
	case *packet.DNSResourceRecordNSEC:
		return x.Name
	case *packet.DNSResourceRecordTLSA:
		return x.Name
	case *packet.DNSResourceRecordSVCB:
		return x.Name
	case *packet.DNSResourceRecordEDNS:
		return x.Name
	case *packet.DNSResourceRecordUnknown:
		return x.Name
	}
	return ""
}
