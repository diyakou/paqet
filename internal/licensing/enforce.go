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
	"path/filepath"
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

type cacheEntry struct {
	Binding    string `json:"binding"`
	ValidatedAt int64  `json:"validated_at"`
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
	binding := bindingKey(base, key, serverID)
	if isCached(binding) {
		return nil
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
	_ = writeCache(binding)
	return nil
}

func bindingKey(base, key, serverID string) string {
	sum := sha256.Sum256([]byte(base + "|" + key + "|" + serverID))
	return hex.EncodeToString(sum[:])
}

func cachePath() string {
	if p := strings.TrimSpace(os.Getenv("PAQET_LICENSE_CACHE")); p != "" {
		return p
	}
	if os.PathSeparator == '\\' {
		programData := strings.TrimSpace(os.Getenv("ProgramData"))
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "paqet", "license-cache.json")
	}
	return "/var/lib/paqet/license-cache.json"
}

func isCached(binding string) bool {
	b, err := os.ReadFile(cachePath())
	if err != nil {
		return false
	}
	var c cacheEntry
	if err := json.Unmarshal(b, &c); err != nil {
		return false
	}
	return strings.TrimSpace(c.Binding) == binding
}

func writeCache(binding string) error {
	p := cachePath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	payload, err := json.Marshal(cacheEntry{
		Binding:    binding,
		ValidatedAt: time.Now().Unix(),
	})
	if err != nil {
		return err
	}
	return os.WriteFile(p, payload, 0o600)
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
