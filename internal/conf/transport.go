package conf

import (
	"fmt"
	"slices"
)

type Transport struct {
	Protocol string `yaml:"protocol"`
	Conn     int    `yaml:"conn"`
	TCPBuf   int    `yaml:"tcpbuf"`
	UDPBuf   int    `yaml:"udpbuf"`
	KCP      *KCP   `yaml:"kcp"`
}

func (t *Transport) setDefaults(role string) {
	// Multiple KCP connections distribute load across streams.
	// For typical deployments, 3 connections keep good parallelism
	// with lower control overhead than 5.
	if t.Conn == 0 {
		t.Conn = 3
	}

	// TCP copy buffer: 32KB provides good throughput for relay workloads.
	// 8KB (old default) causes excessive read/write syscalls under high load.
	if t.TCPBuf == 0 {
		t.TCPBuf = 32 * 1024
	}
	if t.TCPBuf < 4*1024 {
		t.TCPBuf = 4 * 1024
	}
	// UDP copy buffer: 16KB handles most UDP payloads efficiently.
	if t.UDPBuf == 0 {
		t.UDPBuf = 16 * 1024
	}
	if t.UDPBuf < 2*1024 {
		t.UDPBuf = 2 * 1024
	}

	switch t.Protocol {
	case "kcp":
		t.KCP.setDefaults(role)
	}
}

func (t *Transport) validate() []error {
	var errors []error

	validProtocols := []string{"kcp"}
	if !slices.Contains(validProtocols, t.Protocol) {
		errors = append(errors, fmt.Errorf("transport protocol must be one of: %v", validProtocols))
	}

	if t.Conn < 1 || t.Conn > 256 {
		errors = append(errors, fmt.Errorf("KCP conn must be between 1-256 connections"))
	}

	switch t.Protocol {
	case "kcp":
		errors = append(errors, t.KCP.validate()...)
	}

	return errors
}
