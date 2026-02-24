package licensing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"paqet/internal/conf"
)

type activateReq struct {
	License  string `json:"license"`
	ServerID string `json:"server_id"`
}

type activateRes struct {
	OK         bool   `json:"ok"`
	Reason     string `json:"reason"`
	Used       int    `json:"used"`
	Limit      int    `json:"limit"`
	NewlyBound bool   `json:"newly_bound"`
}

func Enforce(cfg *conf.Conf) error {
	base := strings.TrimRight(strings.TrimSpace(cfg.License.URL), "/")
	key := strings.TrimSpace(cfg.License.Key)
	if base == "" || key == "" {
		return fmt.Errorf("license config missing")
	}

	serverID := strings.TrimSpace(cfg.License.ServerID)
	if serverID == "" {
		serverID = computeServerID()
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.License.TimeoutSec)*time.Second)
	defer cancel()

	reqBody, _ := json.Marshal(activateReq{License: key, ServerID: serverID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/activate", bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("license server unreachable: %w", err)
	}
	defer resp.Body.Close()

	// Read small body for error context
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var ar activateRes
	_ = json.Unmarshal(body, &ar)

	if resp.StatusCode != http.StatusOK {
		if ar.Reason == "" {
			ar.Reason = strings.TrimSpace(string(body))
		}
		if ar.Reason == "" {
			ar.Reason = "forbidden"
		}
		return fmt.Errorf("license denied: reason=%s used=%d limit=%d", ar.Reason, ar.Used, ar.Limit)
	}
	if !ar.OK {
		if ar.Reason == "" {
			ar.Reason = "denied"
		}
		return fmt.Errorf("license denied: reason=%s used=%d limit=%d", ar.Reason, ar.Used, ar.Limit)
	}
	return nil
}

func computeServerID() string {
	// Stable per-machine id on Linux; fallback to hostname.
	mid := readFirstNonEmpty(
		"/etc/machine-id",
		"/var/lib/dbus/machine-id",
	)
	host, _ := os.Hostname()

	base := strings.TrimSpace(mid)
	if base == "" {
		base = strings.TrimSpace(host)
	}
	if base == "" {
		base = "unknown"
	}
	combined := base
	if host != "" && !strings.Contains(combined, host) {
		combined = host + "-" + combined
	}
	combined = strings.TrimSpace(combined)
	if len(combined) <= 128 {
		return combined
	}
	sum := sha256.Sum256([]byte(combined))
	return "sid-" + hex.EncodeToString(sum[:])
}

func readFirstNonEmpty(paths ...string) string {
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(b))
		if s != "" {
			return s
		}
	}
	return ""
}
