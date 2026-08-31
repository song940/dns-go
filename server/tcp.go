package server

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/lsongdev/dns-go/packet"
)

// ListenTCP starts a DNS server over TCP at the given address.
func ListenTCP(addr string, handler DNSHandler) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	log.Printf("TCP server listening on %s", addr)
	return serveTCP(ln, handler)
}

// ListenDoT starts a DNS over TLS (RFC 7858) server at the given address.
// certFile and keyFile are the TLS certificate and key files.
// Typical DoT port is 853.
func ListenTLS(addr string, certFile, keyFile string, handler DNSHandler) error {
	// Load TLS certificate
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	return ListenTLSWithConfig(addr, tlsConfig, handler)
}

// ListenDoTWithTLS starts a DNS over TLS server with custom TLS config.
// This allows more control over TLS settings (e.g., custom certificates, client auth).
func ListenTLSWithConfig(addr string, tlsConfig *tls.Config, handler DNSHandler) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	tlsLn := tls.NewListener(ln, tlsConfig)
	defer tlsLn.Close()

	log.Printf("DoT server listening on %s", addr)
	return serveTCP(tlsLn, handler)
}

// serveTCP handles DNS messages over a TCP listener (plain TCP or TLS).
func serveTCP(ln net.Listener, h DNSHandler) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		go handleTCPConn(conn, h)
	}
}

func handleTCPConn(conn net.Conn, h DNSHandler) {
	defer conn.Close()

	for {
		// Read 2-byte length prefix
		lengthBuf := make([]byte, 2)
		_, err := io.ReadFull(conn, lengthBuf)
		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				log.Printf("Error reading length prefix from %s: %v", conn.RemoteAddr(), err)
			}
			return
		}
		msgLen := binary.BigEndian.Uint16(lengthBuf)

		// Read DNS message
		buf := make([]byte, msgLen)
		_, err = io.ReadFull(conn, buf)
		if err != nil {
			log.Printf("Error reading DNS message from %s: %v", conn.RemoteAddr(), err)
			return
		}

		// Parse DNS query
		req, err := packet.FromBytes(buf)
		if err != nil {
			log.Printf("Error decoding packet from %s: %v", conn.RemoteAddr(), err)
			continue
		}

		// Create connection wrapper
		pc := &PackConn{
			Writer:     &tcpResponseWriter{Writer: conn},
			RemoteAddr: conn.RemoteAddr().String(),
			Request:    req,
		}

		// Handle query
		h.HandleQuery(pc)
	}
}

// tcpResponseWriter adds the two-byte message length required by DNS over
// TCP and DNS over TLS. PackConn deliberately deals in raw DNS messages so
// each transport is responsible for its own framing.
type tcpResponseWriter struct {
	io.Writer
}

func (w *tcpResponseWriter) Write(data []byte) (int, error) {
	if len(data) > int(^uint16(0)) {
		return 0, fmt.Errorf("DNS message too large for TCP framing: %d bytes", len(data))
	}
	frame := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(data)))
	copy(frame[2:], data)
	if err := writeFull(w.Writer, frame); err != nil {
		return 0, err
	}
	return len(data), nil
}

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
