package client

import (
	"net"
	"sync"
	"time"

	"github.com/lsongdev/dns-go/packet"
)

type UDPClient struct {
	Server  string
	Timeout time.Duration

	mu   sync.Mutex
	conn net.Conn
}

func NewUDPClient(server string) *UDPClient {
	return &UDPClient{
		Server:  server,
		Timeout: 5 * time.Second,
	}
}

func (client *UDPClient) Query(req *packet.DNSPacket) (res *packet.DNSPacket, err error) {
	client.mu.Lock()
	defer client.mu.Unlock()

	conn, err := client.getConnLocked()
	if err != nil {
		return nil, err
	}

	if err := conn.SetDeadline(time.Now().Add(client.Timeout)); err != nil {
		return nil, err
	}

	_, err = conn.Write(req.Bytes())
	if err != nil {
		client.closeConnLocked()
		return nil, err
	}

	buf := make([]byte, maxDNSMessageSize)
	n, err := conn.Read(buf)
	if err != nil {
		client.closeConnLocked()
		return nil, err
	}

	res, err = packet.FromBytes(buf[:n])
	if err != nil {
		return nil, err
	}
	if err := validateResponse(req, res); err != nil {
		client.closeConnLocked()
		return nil, err
	}
	if res.Header.TC == 1 {
		tcp := NewTCPClient(client.Server)
		tcp.Timeout = client.Timeout
		defer tcp.Close()
		return tcp.Query(req)
	}
	return res, nil
}

// Close closes the underlying UDP connection.
func (client *UDPClient) Close() error {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.closeConnLocked()
}

func (client *UDPClient) getConnLocked() (net.Conn, error) {
	if client.conn != nil {
		return client.conn, nil
	}

	conn, err := net.DialTimeout("udp", client.Server, client.Timeout)
	if err != nil {
		return nil, err
	}

	client.conn = conn
	return conn, nil
}

func (client *UDPClient) closeConnLocked() error {
	if client.conn != nil {
		err := client.conn.Close()
		client.conn = nil
		return err
	}
	return nil
}
