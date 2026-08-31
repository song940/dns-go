package zone

import "testing"

func FuzzParse(f *testing.F) {
	f.Add([]byte("$ORIGIN example.com.\n@ 300 IN A 192.0.2.1\n"))
	f.Add([]byte("example.com. 4294967295W IN A 192.0.2.1\n"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Parse(data)
	})
}
