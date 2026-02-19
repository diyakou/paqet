package conf

import (
	"fmt"
)

// DPI contains DPI (Deep Packet Inspection) evasion settings.
// Inspired by zapret (https://github.com/bol-van/zapret).
//
// These techniques make the tunnel traffic harder for ISP DPI systems
// to detect, classify, and block. All techniques are opt-in (disabled by default).
type DPI struct {
	// --- Technique 1: Fake Packet Injection (zapret --dpi-desync=fake) ---
	//
	// Sends decoy TCP packets with low TTL before real data packets.
	// These packets pass through the ISP's DPI equipment but expire (TTL=0)
	// before reaching the actual destination server.
	//
	// Effect: DPI tries to reassemble the TCP stream including the fake data,
	// resulting in garbage. It can't correctly identify the application protocol,
	// so it doesn't trigger blocking rules.
	//
	// This is SENDER-ONLY — no changes needed on the receiving side.
	FakeEnabled bool `yaml:"fake_packet"`

	// FakeTTL is the IP TTL (or IPv6 Hop Limit) for fake packets.
	// Must be high enough to pass through DPI but low enough to expire
	// before reaching the destination server.
	//
	// For Iran: DPI is typically at ISP level (1-3 hops) or IXP/backbone (3-5 hops).
	// For Russia: TSPU is at ISP and backbone level (2-6 hops).
	//
	// Start with 4 and increase if bypass doesn't work.
	// Use traceroute to find the optimal value.
	// Range: 1-64, Default: 4
	FakeTTL uint8 `yaml:"fake_ttl"`

	// FakeCount is how many fake packets to send before each real packet.
	// More fakes = stronger DPI confusion but more bandwidth overhead.
	// Range: 1-10, Default: 1
	FakeCount int `yaml:"fake_count"`

	// FakeCutoff stops sending fakes after this many real packets per destination.
	// DPI typically only inspects the first few packets of each flow to classify
	// the protocol. After classification, it stops deep inspection.
	// Sending fakes only for the first N packets saves bandwidth while still
	// defeating DPI classification.
	// Range: 1-100, Default: 5
	FakeCutoff int `yaml:"fake_cutoff"`

	// --- Technique 2: Payload Padding (anti length-fingerprinting) ---
	//
	// Adds random bytes to each KCP payload to defeat length-based fingerprinting.
	// KCP packets have predictable sizes (based on MTU) that sophisticated DPI
	// can use to identify the KCP protocol even through encryption.
	//
	// Wire format: [2 bytes: original length] [original payload] [random padding]
	//
	// WARNING: BREAKING CHANGE — both client AND server must have the same
	// padding setting. If one side has padding enabled and the other doesn't,
	// the connection will fail.
	//
	// Default: false (disabled)
	PadEnabled bool `yaml:"padding"`

	// PadMax is the maximum number of random padding bytes added per packet.
	// Actual padding for each packet is randomly chosen between 0 and PadMax.
	// Larger values provide better anti-fingerprinting but increase bandwidth.
	// Range: 1-512, Default: 64
	PadMax int `yaml:"pad_max"`
}

func (d *DPI) setDefaults() {
	if d.FakeTTL == 0 {
		d.FakeTTL = 4
	}
	if d.FakeCount == 0 {
		d.FakeCount = 1
	}
	if d.FakeCutoff == 0 {
		d.FakeCutoff = 5
	}
	if d.PadMax == 0 {
		d.PadMax = 64
	}
}

func (d *DPI) validate() []error {
	var errors []error

	if d.FakeEnabled {
		if d.FakeTTL < 1 || d.FakeTTL > 64 {
			errors = append(errors, fmt.Errorf("DPI fake_ttl must be between 1-64"))
		}
		if d.FakeCount < 1 || d.FakeCount > 10 {
			errors = append(errors, fmt.Errorf("DPI fake_count must be between 1-10"))
		}
		if d.FakeCutoff < 1 || d.FakeCutoff > 100 {
			errors = append(errors, fmt.Errorf("DPI fake_cutoff must be between 1-100"))
		}
	}

	if d.PadEnabled {
		if d.PadMax < 1 || d.PadMax > 512 {
			errors = append(errors, fmt.Errorf("DPI pad_max must be between 1-512"))
		}
	}

	return errors
}
