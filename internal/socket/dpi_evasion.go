package socket

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"paqet/internal/conf"
	"paqet/internal/pkg/hash"
	"sync"
	"sync/atomic"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// dpiEvasion implements zapret-inspired DPI bypass techniques.
//
// Technique 1: Fake Packet Injection (zapret --dpi-desync=fake)
//   Sends decoy TCP packets with low TTL before real data.
//   These packets pass through ISP DPI but expire before the server.
//   DPI's TCP stream reassembly gets corrupted with fake data,
//   preventing it from identifying the tunnel protocol.
//
// Technique 2: Payload Padding (anti length-fingerprinting)
//   Adds random bytes to each payload to randomize packet sizes.
//   Defeats DPI that identifies KCP by its predictable packet lengths.
type dpiEvasion struct {
	cfg         *conf.DPI
	packetCount sync.Map // hash(IP+port) → *atomic.Int64, for fake cutoff
}

func newDPIEvasion(cfg *conf.DPI) *dpiEvasion {
	return &dpiEvasion{cfg: cfg}
}

// shouldSendFake returns true if fake packets should be sent for this destination.
// Tracks per-destination packet count and stops after FakeCutoff.
func (d *dpiEvasion) shouldSendFake(dstIP net.IP, dstPort uint16) bool {
	if !d.cfg.FakeEnabled {
		return false
	}

	key := hash.IPAddr(dstIP, dstPort)
	val, _ := d.packetCount.LoadOrStore(key, new(atomic.Int64))
	counter := val.(*atomic.Int64)
	count := counter.Add(1)
	return count <= int64(d.cfg.FakeCutoff)
}

// sendFakePackets sends N fake decoy packets with low TTL.
// These packets pass through DPI equipment but expire before the destination.
// DPI sees garbage data in the TCP stream → desynchronization → no blocking.
func (h *SendHandle) sendFakePackets(addr *net.UDPAddr) {
	for i := 0; i < h.dpi.cfg.FakeCount; i++ {
		_ = h.writeFakePacket(addr) // best-effort, don't fail real traffic
	}
}

// writeFakePacket constructs and sends a single fake TCP packet with:
//   - Low TTL (expires before reaching server)
//   - Random garbage payload (corrupts DPI stream reassembly)
//   - Valid checksums (DPI won't drop it for being malformed)
//   - Same src/dst as real packets (DPI associates it with the same flow)
func (h *SendHandle) writeFakePacket(addr *net.UDPAddr) error {
	buf := h.bufPool.Get().(gopacket.SerializeBuffer)
	ethLayer := h.ethPool.Get().(*layers.Ethernet)
	defer func() {
		buf.Clear()
		h.bufPool.Put(buf)
		h.ethPool.Put(ethLayer)
	}()

	dstIP := addr.IP
	dstPort := uint16(addr.Port)

	f := h.getClientTCPF(dstIP, dstPort)
	tcpLayer := h.buildTCPHeader(dstPort, f)
	defer h.tcpPool.Put(tcpLayer)

	// Random fake payload between 24-80 bytes.
	// Size varies to avoid creating a new fingerprint from the fakes themselves.
	fakeLen := 24 + cryptoRandIntn(56)
	fakePayload := make([]byte, fakeLen)
	rand.Read(fakePayload)

	var ipLayer gopacket.SerializableLayer
	if dstIP.To4() != nil {
		ip := h.buildIPv4Header(dstIP)
		ip.TTL = h.dpi.cfg.FakeTTL // Low TTL: passes DPI, dies before server
		defer h.ipv4Pool.Put(ip)
		ipLayer = ip
		tcpLayer.SetNetworkLayerForChecksum(ip)
		ethLayer.DstMAC = h.srcIPv4RHWA
		ethLayer.EthernetType = layers.EthernetTypeIPv4
	} else {
		ip := h.buildIPv6Header(dstIP)
		ip.HopLimit = h.dpi.cfg.FakeTTL // Low hop limit: same effect as low TTL
		defer h.ipv6Pool.Put(ip)
		ipLayer = ip
		tcpLayer.SetNetworkLayerForChecksum(ip)
		ethLayer.DstMAC = h.srcIPv6RHWA
		ethLayer.EthernetType = layers.EthernetTypeIPv6
	}

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ethLayer, ipLayer, tcpLayer, gopacket.Payload(fakePayload)); err != nil {
		return err
	}
	return h.handle.WritePacketData(buf.Bytes())
}

// WrapPadding adds random padding to a KCP payload.
// Wire format: [2 bytes: original length (big-endian)] [original payload] [random padding]
// The receiver must call UnwrapPadding to recover the original payload.
func WrapPadding(payload []byte, padMax int) []byte {
	origLen := len(payload)
	padLen := cryptoRandIntn(padMax + 1)

	result := make([]byte, 2+origLen+padLen)
	binary.BigEndian.PutUint16(result[0:2], uint16(origLen))
	copy(result[2:], payload)

	if padLen > 0 {
		rand.Read(result[2+origLen:])
	}

	return result
}

// UnwrapPadding removes padding from a received payload.
// Returns the original payload, or nil if the format is invalid.
func UnwrapPadding(data []byte) []byte {
	if len(data) < 2 {
		return nil
	}
	origLen := int(binary.BigEndian.Uint16(data[0:2]))
	if origLen > len(data)-2 || origLen < 0 {
		return nil // corrupted or invalid
	}
	return data[2 : 2+origLen]
}

// cryptoRandIntn returns a cryptographically random int in [0, n).
func cryptoRandIntn(n int) int {
	if n <= 0 {
		return 0
	}
	var b [2]byte
	rand.Read(b[:])
	return int(binary.BigEndian.Uint16(b[:])) % n
}
