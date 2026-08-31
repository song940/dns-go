package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/pipeline"
	"github.com/lsongdev/dns-go/server"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	handler, err := buildService(cfg)
	if err != nil {
		log.Fatalf("pipeline: %v", err)
	}
	defer handler.Close()

	errCh := make(chan error, len(cfg.Listens))
	for _, l := range cfg.Listens {
		l := l
		go func() {
			log.Printf("listen %-4s %s", l.Type, l.Addr)
			errCh <- listen(l, handler)
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		log.Fatalf("listener error: %v", err)
	case sig := <-sigCh:
		log.Printf("received %v, shutting down", sig)
	}
}

type dnsService interface {
	server.DNSHandler
	Close() error
}

func buildService(cfg *config.Config) (dnsService, error) {
	switch cfg.Mode {
	case "authoritative":
		return pipeline.NewAuthoritativeFromConfig(cfg)
	case "forwarding":
		return pipeline.NewForwardingFromConfig(cfg)
	case "hybrid":
		return pipeline.New(cfg)
	default:
		return nil, fmt.Errorf("unknown mode: %s", cfg.Mode)
	}
}

func listen(l config.ListenSpec, h server.DNSHandler) error {
	switch l.Type {
	case "udp":
		return server.ListenUDP(l.Addr, h)
	case "tcp":
		return server.ListenTCP(l.Addr, h)
	case "tls", "dot":
		return server.ListenTLS(l.Addr, l.CertFile, l.KeyFile, h)
	case "doh", "http":
		return server.ListenHTTP(l.Addr, h)
	default:
		return fmt.Errorf("unknown listen type: %s", l.Type)
	}
}
