package client

import (
	"fmt"
	"io"
	"strings"

	"github.com/lsongdev/dns-go/packet"
)

const maxDNSMessageSize = 65535

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func validateResponse(req, res *packet.DNSPacket) error {
	if req == nil || req.Header == nil {
		return fmt.Errorf("DNS request has no header")
	}
	if res == nil || res.Header == nil {
		return fmt.Errorf("DNS response has no header")
	}
	if res.Header.QR != packet.DNSResponse {
		return fmt.Errorf("received a DNS query instead of a response")
	}
	if res.Header.ID != req.Header.ID {
		return fmt.Errorf("DNS response ID mismatch: got %d, want %d", res.Header.ID, req.Header.ID)
	}
	if len(res.Questions) != len(req.Questions) {
		return fmt.Errorf("DNS response question count mismatch: got %d, want %d", len(res.Questions), len(req.Questions))
	}
	for i := range req.Questions {
		want := req.Questions[i]
		got := res.Questions[i]
		if !strings.EqualFold(strings.TrimSuffix(got.Name, "."), strings.TrimSuffix(want.Name, ".")) ||
			got.Type != want.Type || got.Class != want.Class {
			return fmt.Errorf("DNS response question %d does not match request", i)
		}
	}
	return nil
}
