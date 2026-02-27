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
		// Keep fast2 high-throughput while reducing control-plane packet overhead.
		// - wDelay=true batches writes per KCP interval (fewer small packets)
		// - ackNoDelay=false avoids immediate ACK bursts
		wDelay, ackNoDelay = true, false
	case "fast3":
		noDelay, interval, resend, noCongestion = 1, 10, 2, 1
		wDelay, ackNoDelay = false, true
	case "1to1":
		// Fixed for high-latency/lossy links
		// Congestion control MUST be disabled (noCongestion=1) otherwise speed drops to zero on packet loss.
		noDelay, interval, resend, noCongestion = 1, 20, 2, 1
		wDelay, ackNoDelay = true, false
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
	sconf.KeepAliveInterval = 10 * time.Second  // 10s: lower control traffic and fewer false positives
	sconf.KeepAliveTimeout = 40 * time.Second   // 40s: tolerate transient packet loss without disconnect flaps
	sconf.MaxFrameSize = 32768                  // 32KB: good balance between memory and throughput
	
	// For high connection counts, we need to be careful with memory.
	// If the user hasn't explicitly set large buffers, keep them reasonable.
	if cfg.Smuxbuf == 0 {
		sconf.MaxReceiveBuffer = 4194304 // 4MB default (restored for high speed)
	} else {
		sconf.MaxReceiveBuffer = cfg.Smuxbuf
	}
	
	if cfg.Streambuf == 0 {
		sconf.MaxStreamBuffer = 2097152 // 2MB default (restored for high speed)
	} else {
		sconf.MaxStreamBuffer = cfg.Streambuf
	}
	
	return sconf
}
