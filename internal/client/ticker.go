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
				_ = tc.conn.SetDeadline(time.Now().Add(5 * time.Second))
				err := tc.conn.Ping(true)
				_ = tc.conn.SetDeadline(time.Time{})
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
			}
		case <-ctx.Done():
			return
		}
	}
}
