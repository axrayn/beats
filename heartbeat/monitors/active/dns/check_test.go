package dns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestCheckDNSResult(t *testing.T) {
	tests := []struct {
		name          string
		msg           *dns.Msg
		expectedValue string
		expectedType  string
		expectedError string
	}{
		{
			name: "Valid A record",
			msg: func() *dns.Msg {
				msg := new(dns.Msg)
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET},
					A:   []byte{8, 8, 8, 8},
				})
				return msg
			}(),
			expectedValue: "8.8.8.8",
			expectedType:  "a",
			expectedError: "",
		},
		{
			name: "Invalid A record value",
			msg: func() *dns.Msg {
				msg := new(dns.Msg)
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET},
					A:   []byte{8, 8, 4, 4},
				})
				return msg
			}(),
			expectedValue: "8.8.8.8",
			expectedType:  "a",
			expectedError: "record value of '8.8.4.4' does not match expected value '8.8.8.8'",
		},
		{
			name: "Valid CNAME record",
			msg: func() *dns.Msg {
				msg := new(dns.Msg)
				msg.Answer = append(msg.Answer, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET},
					Target: "alias.example.com.",
				})
				return msg
			}(),
			expectedValue: "alias.example.com.",
			expectedType:  "cname",
			expectedError: "",
		},
		{
			name: "Invalid record type",
			msg: func() *dns.Msg {
				msg := new(dns.Msg)
				msg.Answer = append(msg.Answer, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET},
					Target: "alias.example.com.",
				})
				return msg
			}(),
			expectedValue: "alias.example.com.",
			expectedType:  "a",
			expectedError: "record type of 'cname' does not match expected type 'a'",
		},
		{
			name: "Valid TXT record",
			msg: func() *dns.Msg {
				msg := new(dns.Msg)
				msg.Answer = append(msg.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET},
					Txt: []string{"sample text"},
				})
				return msg
			}(),
			expectedValue: "sample text",
			expectedType:  "txt",
			expectedError: "",
		},
		{
			name: "No matching record",
			msg: func() *dns.Msg {
				msg := new(dns.Msg)
				return msg
			}(),
			expectedValue: "notexist",
			expectedType:  "a",
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkDNSResult(tt.msg, tt.expectedValue, tt.expectedType)
			if tt.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.expectedError)
			}
		})
	}
}
