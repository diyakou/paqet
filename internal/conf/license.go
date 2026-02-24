package conf

import (
	"fmt"
	"net/url"
	"strings"
)

type License struct {
	Key        string `yaml:"key"`
	URL        string `yaml:"url"`
	ServerID   string `yaml:"server_id"`
	TimeoutSec int    `yaml:"timeout_sec"`
}

func (l *License) setDefaults(role string) {
	if l.TimeoutSec == 0 {
		l.TimeoutSec = 6
	}
	if strings.TrimSpace(l.URL) == "" {
		if role == "server" {
			l.URL = "http://paqet-server.morvism.ir:8080"
		} else {
			l.URL = "http://paqet.morvism.ir:8080"
		}
	}
}

func (l *License) validate() []error {
	var errs []error
	if strings.TrimSpace(l.Key) == "" {
		errs = append(errs, fmt.Errorf("license.key is required"))
	}
	if strings.TrimSpace(l.URL) == "" {
		errs = append(errs, fmt.Errorf("license.url is required"))
	} else {
		u, err := url.Parse(l.URL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			errs = append(errs, fmt.Errorf("license.url is invalid"))
		}
	}
	if l.TimeoutSec < 1 || l.TimeoutSec > 30 {
		errs = append(errs, fmt.Errorf("license.timeout_sec must be between 1-30"))
	}
	if sid := strings.TrimSpace(l.ServerID); sid != "" {
		if strings.ContainsAny(sid, " \t\n\r") {
			errs = append(errs, fmt.Errorf("license.server_id must not contain whitespace"))
		}
		if len(sid) > 128 {
			errs = append(errs, fmt.Errorf("license.server_id is too long"))
		}
	}
	return errs
}
