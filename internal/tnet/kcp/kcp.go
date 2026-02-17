package kcp

import (
	"paqet/internal/conf"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

func aplConf(conn *kcp.UDPSession, cfg *conf.KCP) {
	var noDelay, interval, resend, noCongestion int
	var wDelay, ackNoDelay bool
	switch cfg.Mode {
	case "normal":
		noDelay, interval, resend, noCongestion = 0, 40, 2, 1
		wDelay, ackNoDelay = true, false
	case "fast":
		noDelay, interval, resend, noCongestion = 0, 30, 2, 1
		wDelay, ackNoDelay = true, false
	case "fast2":
		noDelay, interval, resend, noCongestion = 1, 20, 2, 1
		wDelay, ackNoDelay = false, true
	case "fast3":
		noDelay, interval, resend, noCongestion = 1, 10, 2, 1
		wDelay, ackNoDelay = false, true
	case "manual":
		noDelay, interval, resend, noCongestion = cfg.NoDelay, cfg.Interval, cfg.Resend, cfg.NoCongestion
		wDelay, ackNoDelay = cfg.WDelay, cfg.AckNoDelay
	}

	conn.SetNoDelay(noDelay, interval, resend, noCongestion)
	conn.SetWindowSize(cfg.Sndwnd, cfg.Rcvwnd)
	conn.SetMtu(cfg.MTU)
	conn.SetWriteDelay(wDelay)
	conn.SetACKNoDelay(ackNoDelay)
	// DSCP 0 (default): blends in with normal traffic.
	// DSCP 46 (EF) is meant for VoIP and attracts ISP/DPI attention.
	conn.SetDSCP(0)
}

func smuxConf(cfg *conf.KCP) *smux.Config {
	var sconf = smux.DefaultConfig()
	sconf.Version = 2
	sconf.KeepAliveInterval = 10 * time.Second  // Was 2s: reduces keepalive overhead by 5x
	sconf.KeepAliveTimeout = 30 * time.Second   // Was 8s: more tolerant of network latency
	sconf.MaxFrameSize = 32768                  // Was 65535: reduces memory per-frame, aligns better with KCP MTU
	sconf.MaxReceiveBuffer = cfg.Smuxbuf
	sconf.MaxStreamBuffer = cfg.Streambuf
	return sconf
}
