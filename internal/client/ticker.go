package client

import (
	"context"
	"paqet/internal/flog"
	"time"
)

const maxHealthCheckFailures = 3

// ticker periodically checks connection health and reconnects dead connections.
// This replaces the old per-request Ping check in newConn() which was a bottleneck.
func (c *Client) ticker(ctx context.Context) {
	// Check one connection per tick (round-robin) to avoid bursty pauses.
	// With N connections, each one is checked every N*6 seconds.
	timer := time.NewTicker(6 * time.Second)
	defer timer.Stop()

	idx := 0

	for {
		select {
		case <-timer.C:
			if len(c.iter.Items) == 0 {
				continue
			}

			i := idx % len(c.iter.Items)
			idx++
			tc := c.iter.Items[i]
			if tc.conn == nil {
				continue
			}

			// Lightweight check: open/close stream only.
			// Avoid setting session-wide deadline which can affect active streams.
			err := tc.conn.Ping(false)
			if err != nil {
				tc.fails++
				flog.Warnf("connection %d health check failed (%d/%d): %v", i, tc.fails, maxHealthCheckFailures, err)
				if tc.fails < maxHealthCheckFailures {
					continue
				}
				flog.Infof("connection %d exceeded health-check failures, reconnecting", i)
				tc.conn.Close()
				newConn, err := tc.createConn()
				if err != nil {
					flog.Errorf("connection %d reconnect failed: %v", i, err)
					continue
				}
				tc.conn = newConn
				tc.fails = 0
				flog.Infof("connection %d reconnected successfully", i)
				continue
			}
			tc.fails = 0
		case <-ctx.Done():
			return
		}
	}
}
