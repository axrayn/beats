package dns

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/elastic/beats/v7/heartbeat/monitors"
	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
)

// Config is the configuration for the DNS monitor.
type Config struct {
	DNSServers []string      `config:"dns_servers" validate:"required"`
	Target     string        `config:"target" validate:"required"`
	Timeout    time.Duration `config:"timeout" validate:"nonzero,positive"`

	Mode monitors.IPSettings `config:",inline"`
	TLS  *tlscommon.Config   `config:"ssl"`

	Transport httpcommon.HTTPTransportSettings `config:",inline"`

	// DNS result validation
	Check checkConfig `config:"check"`
}

type DNSSvr struct {
	U        *url.URL `config:"u"`
	URL      string   `config:"url"`
	Protocol string   `config:"protocol"`
	Address  string   `config:"address"`
	Port     int      `config:"port"`
}

type checkConfig struct {
	Response responseParameters `config:"response"`
}

type responseParameters struct {
	// expected HTTP response configuration
	Authoritative bool   `config:"authoritative"`
	RecordType    string `config:"record_type"`
	Value         string `config:"value"`
}

func defaultConfig() Config {
	cfg := Config{
		Check: checkConfig{
			Response: responseParameters{
				Authoritative: false,
				RecordType:    "",
				Value:         "",
			},
		},
		Transport: httpcommon.DefaultHTTPTransportSettings(),
	}
	cfg.Transport.Timeout = 16 * time.Second

	return cfg
}

// Validate validates of the responseConfig object is valid or not
func (r *responseParameters) Validate() error {
	switch strings.ToLower(r.RecordType) {
	case "a", "aaaa", "cname", "txt":
	default:
		return fmt.Errorf("unknown record type for `record_type`: '%s', please use one of 'a', 'aaaa', 'cname', 'txt'", r.RecordType)
	}
	return nil
}

// ValidateDNS validates if the DNSServers are valid hostnames or IP addresses
func (c *Config) ValidateDNS() error {
	for _, server := range c.DNSServers {
		ds, err := parseDNSSvr(server)
		if err != nil {
			return err
		}
		if net.ParseIP(ds.Address) == nil && !isValidHostname(ds.Address) {
			return fmt.Errorf("invalid DNS server: %s", ds.Address)
		}
	}
	return nil
}

// isValidHostname validates a hostname based on RFC 1123
func isValidHostname(hostname string) bool {
	if len(hostname) > 255 {
		return false
	}
	parts := strings.Split(hostname, ".")
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 || !isAlphanumeric(part) {
			return false
		}
	}
	return true
}

// isAlphanumeric checks if a string is alphanumeric
func isAlphanumeric(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}
