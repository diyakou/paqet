package socket

import (
	"encoding/binary"
	"fmt"
	"net"
	"paqet/internal/conf"
	"runtime"

	"github.com/gopacket/gopacket/pcap"
)

type RecvHandle struct {
	handle  *pcap.Handle
	ipv4Buf net.IP
	ipv6Buf net.IP
}

func NewRecvHandle(cfg *conf.Network) (*RecvHandle, error) {
	handle, err := newHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	// SetDirection is not fully supported on Windows Npcap, so skip it
	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(pcap.DirectionIn); err != nil {
			return nil, fmt.Errorf("failed to set pcap direction in: %v", err)
		}
	}

	filter := fmt.Sprintf("tcp and dst port %d", cfg.Port)
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	return &RecvHandle{
		handle:  handle,
		ipv4Buf: make(net.IP, 4),
		ipv6Buf: make(net.IP, 16),
	}, nil
}

// Read performs zero-alloc direct byte-level parsing instead of full gopacket decode.
// This dramatically reduces CPU and memory usage under high load.
func (h *RecvHandle) Read() ([]byte, net.Addr, error) {
	data, _, err := h.handle.ReadPacketData()
	if err != nil {
		return nil, nil, err
	}

	// Minimum Ethernet frame: 14 bytes header
	if len(data) < 14 {
		return nil, nil, nil
	}

	etherType := binary.BigEndian.Uint16(data[12:14])
	offset := 14

	// Handle VLAN tags (802.1Q)
	if etherType == 0x8100 {
		if len(data) < 18 {
			return nil, nil, nil
		}
		etherType = binary.BigEndian.Uint16(data[16:18])
		offset = 18
	}

	addr := &net.UDPAddr{}
	var ipHeaderLen int

	switch etherType {
	case 0x0800: // IPv4
		if len(data) < offset+20 {
			return nil, nil, nil
		}
		ipHeaderLen = int(data[offset]&0x0F) * 4
		if ipHeaderLen < 20 || len(data) < offset+ipHeaderLen {
			return nil, nil, nil
		}
		// Source IP: bytes 12-15 of IP header (reuse pre-allocated buffer)
		copy(h.ipv4Buf, data[offset+12:offset+16])
		addr.IP = h.ipv4Buf

	case 0x86DD: // IPv6
		if len(data) < offset+40 {
			return nil, nil, nil
		}
		ipHeaderLen = 40
		// Source IP: bytes 8-23 of IPv6 header (reuse pre-allocated buffer)
		copy(h.ipv6Buf, data[offset+8:offset+24])
		addr.IP = h.ipv6Buf

	default:
		return nil, nil, nil
	}

	tcpStart := offset + ipHeaderLen
	// TCP header minimum: 20 bytes (src port at offset 0-1)
	if len(data) < tcpStart+20 {
		return nil, nil, nil
	}

	// Source port: first 2 bytes of TCP header
	addr.Port = int(binary.BigEndian.Uint16(data[tcpStart : tcpStart+2]))

	// TCP data offset (header length): upper 4 bits of byte 12
	tcpHeaderLen := int(data[tcpStart+12]>>4) * 4
	if tcpHeaderLen < 20 || len(data) < tcpStart+tcpHeaderLen {
		return nil, nil, nil
	}

	payloadStart := tcpStart + tcpHeaderLen
	if payloadStart >= len(data) {
		// No payload (e.g. ACK-only packet)
		return nil, nil, nil
	}

	return data[payloadStart:], addr, nil
}

func (h *RecvHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
}
