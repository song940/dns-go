package server

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lsongdev/dns-go/packet"
)

type handlerFunc func(*PackConn)

func (f handlerFunc) HandleQuery(conn *PackConn) { f(conn) }

func testQuery() *packet.DNSPacket {
	req := packet.NewPacket()
	req.AddQuestionA("example.com")
	return req
}

func echoHandler(conn *PackConn) {
	res := packet.NewPacketFromRequest(conn.Request)
	res.Header.RCode = 3
	_ = conn.WriteResponse(res)
}

func TestTCPResponseIsLengthPrefixed(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		handleTCPConn(serverConn, handlerFunc(echoHandler))
		close(done)
	}()

	reqData := testQuery().Bytes()
	frame := make([]byte, 2+len(reqData))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(reqData)))
	copy(frame[2:], reqData)
	if _, err := clientConn.Write(frame); err != nil {
		t.Fatal(err)
	}

	length := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, length); err != nil {
		t.Fatal(err)
	}
	responseData := make([]byte, binary.BigEndian.Uint16(length))
	if _, err := io.ReadFull(clientConn, responseData); err != nil {
		t.Fatal(err)
	}
	res, err := packet.FromBytes(responseData)
	if err != nil {
		t.Fatal(err)
	}
	if res.Header.RCode != 3 {
		t.Fatalf("got rcode %d, want 3", res.Header.RCode)
	}
	_ = clientConn.Close()
	<-done
}

func TestDoHHandlerGETAndPOST(t *testing.T) {
	h := NewHTTPHandler(handlerFunc(echoHandler))
	queryData := testQuery().Bytes()

	tests := []struct {
		name string
		req  *http.Request
	}{
		{
			name: "GET",
			req:  httptest.NewRequest(http.MethodGet, "/dns-query?dns="+base64.RawURLEncoding.EncodeToString(queryData), nil),
		},
		{
			name: "POST",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(queryData))
				r.Header.Set("Content-Type", "application/dns-message")
				return r
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, tt.req)
			if w.Code != http.StatusOK {
				t.Fatalf("got status %d, want 200", w.Code)
			}
			if got := w.Header().Get("Content-Type"); got != "application/dns-message" {
				t.Fatalf("got content type %q", got)
			}
			res, err := packet.FromBytes(w.Body.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			if res.Header.RCode != 3 {
				t.Fatalf("got rcode %d, want 3", res.Header.RCode)
			}
		})
	}
}

func TestDoHHandlerRejectsInvalidRequests(t *testing.T) {
	h := NewHTTPHandler(handlerFunc(echoHandler))

	tests := []struct {
		name       string
		req        *http.Request
		wantStatus int
	}{
		{"missing GET parameter", httptest.NewRequest(http.MethodGet, "/dns-query", nil), http.StatusBadRequest},
		{"wrong POST content type", httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(testQuery().Bytes())), http.StatusBadRequest},
		{"unsupported method", httptest.NewRequest(http.MethodDelete, "/dns-query", nil), http.StatusMethodNotAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, tt.req)
			if w.Code != tt.wantStatus {
				t.Fatalf("got status %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}
