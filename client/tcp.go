package client

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/lsongdev/dns-go/packet"
)

// TCPClient is a DNS client over TCP or TLS.
// DNS over TCP/TLS uses a 2-byte length prefix for each message.
type TCPClient struct {
	Server  string
	Timeout time.Duration

	mu        sync.Mutex
	conn      net.Conn
	useTLS    bool
	tlsConfig *tls.Config
}

// NewTCPClient creates a new DNS over TCP client.
func NewTCPClient(server string) *TCPClient {
	return &TCPClient{
		Server:  server,
		Timeout: 5 * time.Second,
		useTLS:  false,
	}
}

// NewDoTClient creates a new DNS over TLS client (RFC 7858).
// server should be in format "host:port" (typically port 853)
// serverName is used for TLS SNI and certificate verification
func NewTLSClient(server string) *TCPClient {
	serverName, _, _ := net.SplitHostPort(server)
	return NewTLSClientWithConfig(server, &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	})
}

// NewDoTClientWithConfig creates a new DNS over TLS client with custom TLS config.
func NewTLSClientWithConfig(server string, tlsConfig *tls.Config) *TCPClient {
	return &TCPClient{
		Server:    server,
		Timeout:   5 * time.Second,
		useTLS:    true,
		tlsConfig: tlsConfig,
	}
}

// Query sends a DNS query and returns the response.
func (c *TCPClient) Query(req *packet.DNSPacket) (res *packet.DNSPacket, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	conn, err := c.getConnLocked()
	if err != nil {
		return nil, err
	}

	if err := conn.SetDeadline(time.Now().Add(c.Timeout)); err != nil {
		return nil, err
	}

	// Encode the query with 2-byte length prefix
	queryData := req.Bytes()
	if len(queryData) > maxDNSMessageSize {
		return nil, fmt.Errorf("DNS query is too large: %d bytes", len(queryData))
	}
	lengthBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBuf, uint16(len(queryData)))

	// Write length prefix + query data
	if err = writeFull(conn, append(lengthBuf, queryData...)); err != nil {
		c.closeConnLocked()
		return nil, err
	}

	// Read 2-byte length prefix
	lengthBuf = make([]byte, 2)
	_, err = io.ReadFull(conn, lengthBuf)
	if err != nil {
		c.closeConnLocked()
		return nil, err
	}
	msgLen := binary.BigEndian.Uint16(lengthBuf)

	// Read response data
	buf := make([]byte, msgLen)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		c.closeConnLocked()
		return nil, err
	}

	res, err = packet.FromBytes(buf)
	if err != nil {
		return nil, err
	}

	if err := validateResponse(req, res); err != nil {
		c.closeConnLocked()
		return nil, err
	}

	return res, nil
}

// Close closes the underlying connection.
func (c *TCPClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeConnLocked()
}

func (c *TCPClient) getConnLocked() (net.Conn, error) {
	if c.conn != nil {
		return c.conn, nil
	}

	// Plain TCP
	conn, err := net.DialTimeout("tcp", c.Server, c.Timeout)
	if err != nil {
		return nil, err
	}

	if c.useTLS {
		// upgrade plain tcp to tls
		tlsConn := tls.Client(conn, c.tlsConfig)
		if err := tlsConn.SetDeadline(time.Now().Add(c.Timeout)); err != nil {
			conn.Close()
			return nil, err
		}
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, err
		}
		c.conn = tlsConn
		return tlsConn, nil
	}

	c.conn = conn
	return conn, nil
}

func (c *TCPClient) closeConnLocked() error {
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}
