package dns

import (
	"testing"
	"time"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/stretchr/testify/assert"
)

func TestDefaultConfig(t *testing.T) {
	cfg := defaultConfig()

	assert.Equal(t, false, cfg.Check.Response.Authoritative, "Default authoritative should be false")
	assert.Equal(t, "", cfg.Check.Response.RecordType, "Default record type should be empty")
	assert.Equal(t, "", cfg.Check.Response.Value, "Default value should be empty")
	assert.Equal(t, httpcommon.DefaultHTTPTransportSettings(), cfg.Transport, "Default HTTP transport settings should match")
	assert.Equal(t, 16*time.Second, cfg.Transport.Timeout, "Default timeout should be 16 seconds")
}

func TestResponseParametersValidate(t *testing.T) {
	tests := []struct {
		name          string
		recordType    string
		expectedError bool
	}{
		{"Valid A record", "a", false},
		{"Valid AAAA record", "aaaa", false},
		{"Valid CNAME record", "cname", false},
		{"Valid TXT record", "txt", false},
		{"Invalid record", "invalid", true},
		{"Empty record type", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := responseParameters{
				RecordType: tt.recordType,
			}

			err := params.Validate()
			if tt.expectedError {
				assert.Error(t, err, "Expected an error for record type: %s", tt.recordType)
			} else {
				assert.NoError(t, err, "Did not expect an error for record type: %s", tt.recordType)
			}
		})
	}
}

func TestValidateDNS(t *testing.T) {
	tests := []struct {
		name          string
		dnsServers    []string
		expectedError bool
	}{
		{"Valid IP addresses", []string{"8.8.8.8", "8.8.4.4"}, false},
		{"Valid hostnames", []string{"dns.google", "example.com"}, false},
		{"Invalid DNS server", []string{"invalid..hostname", "256.256.256.256"}, true},
		{"Mixed valid and invalid", []string{"8.8.8.8", "invalid..hostname"}, true},
		{"Empty list", []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				DNSServers: tt.dnsServers,
			}

			err := cfg.ValidateDNS()
			if tt.expectedError {
				assert.Error(t, err, "Expected an error for DNS servers: %v", tt.dnsServers)
			} else {
				assert.NoError(t, err, "Did not expect an error for DNS servers: %v", tt.dnsServers)
			}
		})
	}
}
