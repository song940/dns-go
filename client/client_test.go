package client

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/lsongdev/dns-go/packet"
)

func clientTestQuery() *packet.DNSPacket {
	req := packet.NewPacket()
	req.AddQuestionA("example.com")
	return req
}

func nxdomainResponse(req *packet.DNSPacket) *packet.DNSPacket {
	res := packet.NewPacketFromRequest(req)
	res.Header.QR = packet.DNSResponse
	res.Header.RCode = 3
	return res
}

func TestUDPClientReturnsNXDOMAINAsResponse(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	serverErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 65535)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			serverErr <- err
			return
		}
		req, err := packet.FromBytes(buf[:n])
		if err != nil {
			serverErr <- err
			return
		}
		_, err = conn.WriteTo(nxdomainResponse(req).Bytes(), addr)
		serverErr <- err
	}()

	c := NewUDPClient(conn.LocalAddr().String())
	c.Timeout = time.Second
	defer c.Close()
	res, err := c.Query(clientTestQuery())
	if err != nil {
		t.Fatal(err)
	}
	if res.Header.RCode != 3 {
		t.Fatalf("got rcode %d, want 3", res.Header.RCode)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestTCPClientReturnsNXDOMAINAsResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		length := make([]byte, 2)
		if _, err := io.ReadFull(conn, length); err != nil {
			serverErr <- err
			return
		}
		data := make([]byte, binary.BigEndian.Uint16(length))
		if _, err := io.ReadFull(conn, data); err != nil {
			serverErr <- err
			return
		}
		req, err := packet.FromBytes(data)
		if err != nil {
			serverErr <- err
			return
		}
		responseData := nxdomainResponse(req).Bytes()
		frame := make([]byte, 2+len(responseData))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(responseData)))
		copy(frame[2:], responseData)
		serverErr <- writeFull(conn, frame)
	}()

	c := NewTCPClient(ln.Addr().String())
	c.Timeout = time.Second
	defer c.Close()
	res, err := c.Query(clientTestQuery())
	if err != nil {
		t.Fatal(err)
	}
	if res.Header.RCode != 3 {
		t.Fatalf("got rcode %d, want 3", res.Header.RCode)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestUDPClientFallsBackToTCPWhenTruncated(t *testing.T) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	udpConn, err := net.ListenPacket("udp", tcpLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	udpErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 65535)
		n, addr, err := udpConn.ReadFrom(buf)
		if err != nil {
			udpErr <- err
			return
		}
		req, err := packet.FromBytes(buf[:n])
		if err != nil {
			udpErr <- err
			return
		}
		res := packet.NewPacketFromRequest(req)
		res.Header.QR = packet.DNSResponse
		res.Header.TC = 1
		_, err = udpConn.WriteTo(res.Bytes(), addr)
		udpErr <- err
	}()

	tcpErr := make(chan error, 1)
	go func() {
		conn, err := tcpLn.Accept()
		if err != nil {
			tcpErr <- err
			return
		}
		defer conn.Close()
		length := make([]byte, 2)
		if _, err := io.ReadFull(conn, length); err != nil {
			tcpErr <- err
			return
		}
		data := make([]byte, binary.BigEndian.Uint16(length))
		if _, err := io.ReadFull(conn, data); err != nil {
			tcpErr <- err
			return
		}
		req, err := packet.FromBytes(data)
		if err != nil {
			tcpErr <- err
			return
		}
		res := packet.NewPacketFromRequest(req)
		res.Header.QR = packet.DNSResponse
		res.AddAnswer(&packet.DNSResourceRecordA{
			DNSResourceRecord: packet.DNSResourceRecord{Name: "example.com", Type: packet.DNSTypeA, Class: packet.DNSClassIN, TTL: 60},
			Address:           "192.0.2.1",
		})
		responseData := res.Bytes()
		frame := make([]byte, 2+len(responseData))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(responseData)))
		copy(frame[2:], responseData)
		tcpErr <- writeFull(conn, frame)
	}()

	c := NewUDPClient(udpConn.LocalAddr().String())
	c.Timeout = time.Second
	defer c.Close()
	res, err := c.Query(clientTestQuery())
	if err != nil {
		t.Fatal(err)
	}
	if res.Header.TC != 0 || len(res.Answers) != 1 {
		t.Fatalf("expected complete TCP response, got TC=%d answers=%d", res.Header.TC, len(res.Answers))
	}
	if err := <-udpErr; err != nil {
		t.Fatal(err)
	}
	if err := <-tcpErr; err != nil {
		t.Fatal(err)
	}
}
