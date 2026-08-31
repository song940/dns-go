package packet

import "testing"

func FuzzFromBytes(f *testing.F) {
	query := NewPacket()
	query.AddQuestionA("example.com")
	f.Add(query.Bytes())
	f.Add([]byte{})
	f.Add(append((&DNSHeader{QDCount: 1}).Bytes(), 0xc0, 0x0c))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = FromBytes(data)
	})
}
