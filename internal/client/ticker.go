package client

import (
	"context"
	"paqet/internal/flog"
	"time"
)

const maxHealthCheckFailures = 4

// ticker periodically checks connection health and reconnects dead connections.
// This replaces the old per-request Ping check in newConn() which was a bottleneck.
func (c *Client) ticker(ctx context.Context) {
	// Conservative health-check cadence to avoid false reconnect flaps
	// on transient loss/jittery links.
	timer := time.NewTicker(15 * time.Second)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			for i, tc := range c.iter.Items {
				if tc.conn == nil {
					continue
				}

				// Use real ping/pong for health checks so the server can handle the stream
				// as protocol traffic rather than EOF noise.
				err := tc.conn.Ping(true)
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
