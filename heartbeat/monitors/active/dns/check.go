package dns

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

func checkDNSResult(r *dns.Msg, eValue string, eType string) error {
	for _, a := range r.Answer {
		var value string
		var record_type string
		switch v := a.(type) {
		case *dns.A:
			value = v.A.String()
			record_type = "a"
		case *dns.AAAA:
			value = v.AAAA.String()
			record_type = "aaaa"
		case *dns.CNAME:
			value = v.Target
			record_type = "cname"
		case *dns.TXT:
			value = strings.Join(v.Txt, " ")
			record_type = "txt"
		default:
			continue
		}

		if (eValue != "") && (eValue != strings.ToLower(value)) {
			return fmt.Errorf("record value of '%s' does not match expected value '%s'", strings.ToLower(value), eValue)
		} else if (eType != "") && (eType != record_type) {
			return fmt.Errorf("record type of '%s' does not match expected type '%s'", record_type, eType)
		}
	}
	return nil
}
