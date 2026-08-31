package server

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/lsongdev/dns-go/packet"
)

const maxDNSMessageSize = 65535

func ListenHTTP(addr string, handler DNSHandler) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           NewHTTPHandler(handler),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return srv.ListenAndServe()
}

// NewHTTPHandler returns an RFC 8484 DNS-over-HTTPS handler. TLS termination
// may happen in this process or in a trusted reverse proxy.
func NewHTTPHandler(handler DNSHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := readDoHRequest(r)
		if err != nil {
			status := http.StatusBadRequest
			var methodErr *methodNotAllowedError
			if errors.As(err, &methodErr) {
				w.Header().Set("Allow", "GET, POST")
				status = http.StatusMethodNotAllowed
			}
			http.Error(w, err.Error(), status)
			return
		}
		req, err := packet.FromBytes(data)
		if err != nil {
			http.Error(w, "invalid DNS message", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		conn := &PackConn{
			Writer:     w,
			Request:    req,
			RemoteAddr: r.RemoteAddr,
		}
		handler.HandleQuery(conn)
	})
}

func readDoHRequest(r *http.Request) ([]byte, error) {
	switch r.Method {
	case http.MethodGet:
		encoded := r.URL.Query().Get("dns")
		if encoded == "" {
			return nil, fmt.Errorf("missing dns query parameter")
		}
		data, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("invalid dns query parameter")
		}
		if len(data) > maxDNSMessageSize {
			return nil, fmt.Errorf("DNS message too large")
		}
		return data, nil
	case http.MethodPost:
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/dns-message" {
			return nil, fmt.Errorf("content type must be application/dns-message")
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxDNSMessageSize+1))
		if err != nil {
			return nil, fmt.Errorf("read DNS message: %w", err)
		}
		if len(body) > maxDNSMessageSize {
			return nil, fmt.Errorf("DNS message too large")
		}
		return body, nil
	default:
		return nil, &methodNotAllowedError{method: r.Method}
	}
}

type methodNotAllowedError struct{ method string }

func (e *methodNotAllowedError) Error() string { return "method not allowed: " + e.method }
