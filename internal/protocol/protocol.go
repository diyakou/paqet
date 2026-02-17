package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"paqet/internal/conf"
	"paqet/internal/tnet"
)

type PType = byte

const (
	PPING PType = 0x01
	PPONG PType = 0x02
	PTCPF PType = 0x03
	PTCP  PType = 0x04
	PUDP  PType = 0x05
)

type Proto struct {
	Type PType
	Addr *tnet.Addr
	TCPF []conf.TCPF
}

// Read performs efficient binary decoding instead of gob.
// Wire format:
//
//	[1 byte: Type]
//	[2 bytes: addr len (big-endian), N bytes: addr string]  (if Type == PTCP or PUDP)
//	[1 byte: TCPF count, N bytes: TCPF flags]                (if Type == PTCPF)
func (p *Proto) Read(r io.Reader) error {
	var typeBuf [1]byte
	if _, err := io.ReadFull(r, typeBuf[:]); err != nil {
		return err
	}
	p.Type = typeBuf[0]

	switch p.Type {
	case PTCP, PUDP:
		// Read addr length (2 bytes) + addr string
		var lenBuf [2]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return err
		}
		addrLen := binary.BigEndian.Uint16(lenBuf[:])
		if addrLen > 512 {
			return fmt.Errorf("address too long: %d", addrLen)
		}
		addrBuf := make([]byte, addrLen)
		if _, err := io.ReadFull(r, addrBuf); err != nil {
			return err
		}
		addr, err := tnet.NewAddr(string(addrBuf))
		if err != nil {
			return err
		}
		p.Addr = addr

	case PTCPF:
		// Read TCPF count (1 byte) + flags
		var countBuf [1]byte
		if _, err := io.ReadFull(r, countBuf[:]); err != nil {
			return err
		}
		count := int(countBuf[0])
		if count > 64 {
			return fmt.Errorf("too many TCPF entries: %d", count)
		}
		p.TCPF = make([]conf.TCPF, count)
		for i := 0; i < count; i++ {
			var flagBuf [2]byte
			if _, err := io.ReadFull(r, flagBuf[:]); err != nil {
				return err
			}
			flags := binary.BigEndian.Uint16(flagBuf[:])
			p.TCPF[i] = decodeTCPF(flags)
		}

	case PPING, PPONG:
		// No additional data
	default:
		return fmt.Errorf("unknown protocol type: %d", p.Type)
	}
	return nil
}

// Write performs efficient binary encoding instead of gob.
func (p *Proto) Write(w io.Writer) error {
	if _, err := w.Write([]byte{p.Type}); err != nil {
		return err
	}

	switch p.Type {
	case PTCP, PUDP:
		if p.Addr == nil {
			return fmt.Errorf("address is required for TCP/UDP")
		}
		addrStr := p.Addr.String()
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(addrStr)))
		if _, err := w.Write(lenBuf[:]); err != nil {
			return err
		}
		if _, err := w.Write([]byte(addrStr)); err != nil {
			return err
		}

	case PTCPF:
		count := len(p.TCPF)
		if _, err := w.Write([]byte{byte(count)}); err != nil {
			return err
		}
		for _, f := range p.TCPF {
			var flagBuf [2]byte
			binary.BigEndian.PutUint16(flagBuf[:], encodeTCPF(f))
			if _, err := w.Write(flagBuf[:]); err != nil {
				return err
			}
		}

	case PPING, PPONG:
		// No additional data
	}

	return nil
}

func encodeTCPF(f conf.TCPF) uint16 {
	var flags uint16
	if f.FIN {
		flags |= 1 << 0
	}
	if f.SYN {
		flags |= 1 << 1
	}
	if f.RST {
		flags |= 1 << 2
	}
	if f.PSH {
		flags |= 1 << 3
	}
	if f.ACK {
		flags |= 1 << 4
	}
	if f.URG {
		flags |= 1 << 5
	}
	if f.ECE {
		flags |= 1 << 6
	}
	if f.CWR {
		flags |= 1 << 7
	}
	if f.NS {
		flags |= 1 << 8
	}
	return flags
}

func decodeTCPF(flags uint16) conf.TCPF {
	return conf.TCPF{
		FIN: flags&(1<<0) != 0,
		SYN: flags&(1<<1) != 0,
		RST: flags&(1<<2) != 0,
		PSH: flags&(1<<3) != 0,
		ACK: flags&(1<<4) != 0,
		URG: flags&(1<<5) != 0,
		ECE: flags&(1<<6) != 0,
		CWR: flags&(1<<7) != 0,
		NS:  flags&(1<<8) != 0,
	}
}
