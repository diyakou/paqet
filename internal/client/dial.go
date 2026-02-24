package client

import (
	"fmt"
	"paqet/internal/flog"
	"paqet/internal/tnet"
	"time"
)

const maxRetries = 3

// newConn returns the next available connection using lock-free round-robin.
// No mutex needed: iterator uses atomic counter, and connection health is
// checked lazily. This eliminates the main bottleneck for 200+ concurrent users.
func (c *Client) newConn() (tnet.Conn, error) {
	tc := c.iter.Next()
	if tc.conn == nil {
		return nil, fmt.Errorf("connection not initialized")
	}
	return tc.conn, nil
}

func (c *Client) newStrm() (tnet.Strm, error) {
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 50ms, 100ms
			backoff := time.Duration(50<<uint(attempt-1)) * time.Millisecond
			flog.Debugf("stream creation retry %d/%d after %v", attempt+1, maxRetries, backoff)
			time.Sleep(backoff)
		}

		conn, err := c.newConn()
		if err != nil {
			lastErr = err
			flog.Debugf("session creation failed (attempt %d/%d): %v", attempt+1, maxRetries, err)
			continue
		}
		strm, err := conn.OpenStrm()
		if err != nil {
			lastErr = err
			flog.Debugf("failed to open stream (attempt %d/%d): %v", attempt+1, maxRetries, err)
			continue
		}
		return strm, nil
	}
	return nil, fmt.Errorf("failed to create stream after %d attempts: %w", maxRetries, lastErr)
}
