package client

import (
	"context"
	"paqet/internal/flog"
	"time"
)

// ticker periodically checks connection health and reconnects dead connections.
// This replaces the old per-request Ping check in newConn() which was a bottleneck.
func (c *Client) ticker(ctx context.Context) {
	// Reduce control traffic while still detecting dead links in reasonable time.
	timer := time.NewTicker(30 * time.Second)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			for i, tc := range c.iter.Items {
				if tc.conn == nil {
					continue
				}
				err := tc.conn.Ping(false)
				if err != nil {
					flog.Infof("connection %d health check failed, reconnecting: %v", i, err)
					tc.conn.Close()
					newConn, err := tc.createConn()
					if err != nil {
						flog.Errorf("connection %d reconnect failed: %v", i, err)
						continue
					}
					tc.conn = newConn
					flog.Infof("connection %d reconnected successfully", i)
				}
			}
		case <-ctx.Done():
			return
		}
	}
}
