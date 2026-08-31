package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/lsongdev/dns-go/packet"
)

// HTTPClient is a DNS over HTTPS (DoH) client (RFC 8484).
// Supports both GET and POST methods.
// Uses HTTP/2 which is required by most DoH servers.
type HTTPClient struct {
	Server  string
	Timeout time.Duration
	UsePost bool // Use POST method instead of GET

	once   sync.Once
	client *http.Client
}

// NewHTTPClient creates a new DoH client.
// server should be a full URL like "https://cloudflare-dns.com/dns-query"
func NewHTTPClient(server string) *HTTPClient {
	return &HTTPClient{
		Server:  server,
		Timeout: 5 * time.Second,
		UsePost: false,
	}
}

// NewHTTPClientPost creates a new DoH client using POST method.
// POST is recommended by RFC 8484 and has better compatibility.
func NewHTTPClientPost(server string) *HTTPClient {
	return &HTTPClient{
		Server:  server,
		Timeout: 5 * time.Second,
		UsePost: true,
	}
}

// createHTTPClient creates an HTTP client with HTTP/2 support.
func createHTTPClient(timeout time.Duration) *http.Client {
	// Create transport with HTTP/2 support
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: timeout,
		ForceAttemptHTTP2:   true, // Enable HTTP/2
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

// Query sends a DNS query and returns the response.
func (c *HTTPClient) Query(query *packet.DNSPacket) (res *packet.DNSPacket, err error) {
	queryData := query.Bytes()
	httpClient := c.getHTTPClient()

	var req *http.Request
	if c.UsePost {
		// POST request (RFC 8484 recommended)
		req, err = http.NewRequest(http.MethodPost, c.Server, bytes.NewReader(queryData))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/dns-message")
	} else {
		// GET request
		b64Req := base64.RawURLEncoding.EncodeToString(queryData)
		u, parseErr := url.Parse(c.Server)
		if parseErr != nil {
			return nil, parseErr
		}
		params := u.Query()
		params.Set("dns", b64Req)
		u.RawQuery = params.Encode()
		req, err = http.NewRequest(http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
	}

	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "dns-go")

	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned status %d", resp.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/dns-message" {
		return nil, fmt.Errorf("DoH server returned content type %q", resp.Header.Get("Content-Type"))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSMessageSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxDNSMessageSize {
		return nil, fmt.Errorf("DoH response is too large")
	}
	res, err = packet.FromBytes(body)
	if err != nil {
		return nil, err
	}
	if err := validateResponse(query, res); err != nil {
		return nil, err
	}
	return res, nil
}

func (c *HTTPClient) Close() error {
	c.getHTTPClient().CloseIdleConnections()
	return nil
}

func (c *HTTPClient) getHTTPClient() *http.Client {
	c.once.Do(func() {
		c.client = createHTTPClient(c.Timeout)
	})
	return c.client
}
