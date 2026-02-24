package server

import (
	"context"
	"net"
	"paqet/internal/flog"
	"paqet/internal/pkg/buffer"
	"paqet/internal/protocol"
	"paqet/internal/tnet"
	"time"
)

func (s *Server) handleTCPProtocol(ctx context.Context, strm tnet.Strm, p *protocol.Proto) error {
	flog.Infof("accepted TCP stream %d: %s -> %s", strm.SID(), strm.RemoteAddr(), p.Addr.String())
	return s.handleTCP(ctx, strm, p.Addr.String())
}

func (s *Server) handleTCP(ctx context.Context, strm tnet.Strm, addr string) error {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		flog.Errorf("failed to establish TCP connection to %s for stream %d: %v", addr, strm.SID(), err)
		return err
	}
	defer func() {
		conn.Close()
		flog.Debugf("closed TCP connection %s for stream %d", addr, strm.SID())
	}()
	flog.Debugf("TCP connection established to %s for stream %d", addr, strm.SID())

	// Use context cancellation to properly tear down both directions
	// when one side closes. Prevents goroutine leaks.
	copyCtx, copyCancel := context.WithCancel(ctx)
	defer copyCancel()

	errChan := make(chan error, 2)
	go func() {
		err := buffer.CopyT(conn, strm)
		copyCancel() // Signal the other direction to stop
		errChan <- err
	}()
	go func() {
		err := buffer.CopyT(strm, conn)
		copyCancel() // Signal the other direction to stop
		errChan <- err
	}()

	// Wait for context cancellation (either copy finished or parent cancelled)
	<-copyCtx.Done()

	// Close connections to unblock any stuck reads
	conn.Close()
	strm.Close()

	// Drain error channel
	for i := 0; i < 2; i++ {
		if e := <-errChan; e != nil && err == nil {
			err = e
		}
	}
	if err != nil {
		flog.Debugf("TCP stream %d to %s finished with: %v", strm.SID(), addr, err)
	}
	return nil
}
