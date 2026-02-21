package socket

import (
	"fmt"
	"paqet/internal/conf"
	"runtime"

	"github.com/gopacket/gopacket/pcap"
)

func newHandle(cfg *conf.Network) (*pcap.Handle, error) {
	// On Windows, use the GUID field to construct the NPF device name
	// On other platforms, use the interface name directly
	ifaceName := cfg.Interface.Name
	if runtime.GOOS == "windows" {
		ifaceName = cfg.GUID
	}

	inactive, err := pcap.NewInactiveHandle(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to create inactive pcap handle for %s: %v", cfg.Interface.Name, err)
	}
	defer inactive.CleanUp()

	if err = inactive.SetBufferSize(cfg.PCAP.Sockbuf); err != nil {
		return nil, fmt.Errorf("failed to set pcap buffer size to %d: %v", cfg.PCAP.Sockbuf, err)
	}

	// SnapLen 2048 is optimal: KCP MTU ~1350 + TCP/IP/Ethernet headers (~300 bytes) = ~1650 bytes.
	// 2048 aligns with page boundaries and avoids excess memory copies on high-load packet bursts.
	if err = inactive.SetSnapLen(2048); err != nil {
		return nil, fmt.Errorf("failed to set pcap snap length: %v", err)
	}
	// Promiscuous mode is NOT needed: BPF filter already selects our port.
	// Disabling it avoids capturing and processing irrelevant traffic,
	// which is a major CPU saver on busy servers.
	if err = inactive.SetPromisc(false); err != nil {
		return nil, fmt.Errorf("failed to disable promiscuous mode: %v", err)
	}
	if err = inactive.SetTimeout(pcap.BlockForever); err != nil {
		return nil, fmt.Errorf("failed to set pcap timeout: %v", err)
	}
	if err = inactive.SetImmediateMode(true); err != nil {
		return nil, fmt.Errorf("failed to enable immediate mode: %v", err)
	}

	handle, err := inactive.Activate()
	if err != nil {
		return nil, fmt.Errorf("failed to activate pcap handle on %s: %v", cfg.Interface.Name, err)
	}

	return handle, nil
}
