package dns

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elastic/beats/v7/heartbeat/ecserr"
	"github.com/elastic/beats/v7/heartbeat/eventext"
	"github.com/elastic/beats/v7/heartbeat/look"
	"github.com/elastic/beats/v7/heartbeat/monitors"
	"github.com/elastic/beats/v7/heartbeat/monitors/active/dialchain/tlsmeta"
	"github.com/elastic/beats/v7/heartbeat/monitors/jobs"
	"github.com/elastic/beats/v7/heartbeat/monitors/plugin"
	"github.com/elastic/beats/v7/heartbeat/monitors/wrappers/wraputil"
	"github.com/elastic/beats/v7/heartbeat/reason"
	"github.com/elastic/beats/v7/libbeat/beat"
	conf "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/mapstr"

	//"github.com/elastic/elastic-agent-libs/transport"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/miekg/dns"
)

// Register the DNS monitor type.
func init() {
	plugin.Register("dns", create, "synthetics/dns")
}

// Create makes a new DNS monitor
func create(
	name string,
	cfg *conf.C,
) (p plugin.Plugin, err error) {
	config := defaultConfig()
	if err := cfg.Unpack(&config); err != nil {
		return plugin.Plugin{}, err
	}

	var makeJob func(DNSSvr) (jobs.Job, error)

	// Check that the DNS Servers and hostnames are valid
	if err := config.ValidateDNS(); err != nil {
		return plugin.Plugin{}, err
	}

	// preload TLS configuration
	tlscfg, err := tlscommon.LoadTLSConfig(config.TLS)
	if err != nil {
		return plugin.Plugin{}, err
	}
	config.TLS = nil

	makeJob = func(dnsSvr DNSSvr) (jobs.Job, error) {
		return newDNSMonitorJob(&config, dnsSvr, tlscfg)
	}

	js := make([]jobs.Job, len(config.DNSServers))
	for i, dnsAddr := range config.DNSServers {
		dnsSvr, _ := parseDNSSvr(dnsAddr)
		job, err := makeJob(dnsSvr)
		if err != nil {
			return plugin.Plugin{}, err
		}
		js[i] = wraputil.WithURLField(dnsSvr.U, job)
	}

	return plugin.Plugin{Jobs: js, Endpoints: len(config.DNSServers)}, nil
}

func newDNSMonitorJob(
	config *Config,
	dnssvr DNSSvr,
	tlscfg *tlscommon.TLSConfig,
) (jobs.Job, error) {

	pingFactory := createPingFactory(config, &dnssvr, tlscfg)
	job, err := monitors.MakeByHostJob(dnssvr.Address, config.Mode, monitors.NewStdResolver(), pingFactory)

	return job, err
}

func createPingFactory(
	config *Config,
	dnssvr *DNSSvr,
	tlscfg *tlscommon.TLSConfig,
) func(*net.IPAddr) jobs.Job {
	timeout := config.Transport.Timeout

	return monitors.MakePingIPFactory(func(event *beat.Event, ip *net.IPAddr) error {
		var (
			writeStart, readStart, writeEnd time.Time
		)
		// Ensure memory consistency for these callbacks.
		// It seems they can be invoked still sometime after the request is done
		cbMutex := sync.Mutex{}

		client := &dns.Client{
			Net:     "udp",
			Timeout: config.Timeout,
		}

		fmt.Printf("\n****DEBUG Config: %+v\n\n", config)

		// Must have the DNS Svr scheme at 'tcp' for 'tcp-tls' mode to work.
		if config.Transport.TLS != nil && dnssvr.U.Scheme == "tcp" {
			client.Net = "tcp-tls"
			client.TLSConfig = tlscfg.ToConfig()
		}

		end, err := execPing(event, client, dnssvr, config, timeout)
		cbMutex.Lock()
		defer cbMutex.Unlock()

		if !readStart.IsZero() {
			eventext.MergeEventFields(event, mapstr.M{
				"dns": mapstr.M{
					"rtt": mapstr.M{
						"write_request":   look.RTT(writeEnd.Sub(writeStart)),
						"response_header": look.RTT(readStart.Sub(writeStart)),
					},
				},
			})
		}
		if !writeStart.IsZero() {
			_, _ = event.PutValue("dns.rtt.validate", look.RTT(end.Sub(writeStart)))
			_, _ = event.PutValue("dns.rtt.content", look.RTT(end.Sub(readStart)))
		}

		return err
	})
}

func execPing(
	event *beat.Event,
	client *dns.Client,
	dnssvr *DNSSvr,
	config *Config,
	timeout time.Duration,
) (end time.Time, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req := DNSRequest{Server: dnssvr, Target: config.Target}

	// Send the DNS request. We don't immediately return on error since
	// we may want to add additional fields to contextualize the error.
	start, resp, errReason := execRequest(ctx, client, &req)
	// If we have no response object or an error was set there probably was an IO error, we can skip the rest of the logic
	// since that logic is for adding metadata relating to completed HTTP transactions that have errored
	// in other ways
	if resp == nil || errReason != nil {
		var ecsErr *ecserr.ECSErr
		var urlError *url.Error
		if errors.As(errReason.Unwrap(), &ecsErr) {
			return time.Now(), ecsErr
		} else if errors.As(errReason.Unwrap(), &urlError) {
			var certErr x509.CertificateInvalidError
			if errors.As(urlError, &certErr) {
				tlsFields := tlsmeta.CertFields(certErr.Cert, nil)
				event.Fields.DeepUpdate(mapstr.M{"tls": tlsFields})

			}
		}

		return time.Now(), errReason
	}

	var ansSlice []mapstr.M
	for _, rsp := range resp.Answer {
		ansFields := mapstr.M{
			"record_type": rsp.RRType,
			"value":       rsp.Value,
			"name":        rsp.Name,
		}
		ansSlice = append(ansSlice, ansFields)
	}

	fmt.Printf("\n***DEBUG resp.Answer: %+v\n\n", resp.Answer)

	responseFields := mapstr.M{
		"server":  resp.DNSServer,
		"answers": ansSlice,
	}

	dnsFields := mapstr.M{"response": responseFields}

	eventext.MergeEventFields(event, mapstr.M{"dns": dnsFields})

	// Mark the end time as now, since we've finished downloading
	end = time.Now()

	// Enrich event with TLS information when available. This is useful when connecting to DNS over TLS.
	if resp.TLS.ServerName != "" {
		tlsFields := mapstr.M{}
		//tlsmeta.AddTLSMetadata(tlsFields, *resp.TLS, tlsmeta.UnknownTLSHandshakeDuration)
		eventext.MergeEventFields(event, tlsFields)
	}

	// Add total HTTP RTT
	eventext.MergeEventFields(event, mapstr.M{"dns": mapstr.M{
		"rtt": mapstr.M{
			"total": look.RTT(end.Sub(start)),
		},
	}})

	return end, errReason
}

// execute the request. Note that this does not close the resp body, which should be done by caller
func execRequest(ctx context.Context, client *dns.Client, req *DNSRequest) (start time.Time, resp *DNSResponse, errReason reason.Reason) {
	start = time.Now()
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(req.Target), dns.TypeANY)
	msg.RecursionDesired = true

	var r *dns.Msg
	var err error

	r, _, err = client.ExchangeContext(ctx, msg, req.Server.Address+":"+fmt.Sprintf("%d", req.Server.Port))
	//if err == nil && r != nil {
	//	connState = client.TLSConnectionState
	//}
	if err != nil {
		err = ecserr.NewCouldNotConnectErr(req.Server.Address, fmt.Sprintf("%d", req.Server.Port), err)
		return start, nil, reason.IOFailed(err)
	}

	var DNSResp DNSResponse
	var answers []DNSAnswer

	fmt.Printf("\n***DEBUG Answers: %+v\n\n", r.Answer)
	fmt.Printf("\n***DEBUG NS: %+v\n\n", r.Ns)
	fmt.Printf("\n***DEBUG Extra: %+v\n\n", r.Extra)

	fmt.Printf("\n***DEBUG Response: %+v\n\n", r)

	if r.Answer != nil {
		fmt.Printf("\n***DEBUG haveAnswers!\n")
		for _, a := range r.Answer {
			var value, record_type string
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
			value = strings.ToLower(value)
			d := DNSAnswer{Name: strings.ToLower(a.Header().Name), TTL: int(a.Header().Header().Ttl), RRType: record_type, Value: value}
			fmt.Printf("\n***DEBUG Answer: %+v\n\n", d)
			answers = append(answers, d)
		}
	}
	DNSResp.Answer = answers
	DNSResp.DNSServer = req.Server.URL

	return start, &DNSResp, nil
}

func parseDNSSvr(addr string) (DNSSvr, error) {
	var ds DNSSvr

	// Parse the passed string into a net.URL object
	u, err := url.Parse(strings.ToLower(addr))
	if err != nil {
		// Madness because URL.Parse bombs when you specify a port
		// but not a scheme. Prepend udp:// as the default
		addr = "udp://" + addr
		u2, err := url.Parse(strings.ToLower(addr))
		if err != nil {
			return ds, err
		}
		u = u2
	}

	/*
		If we don't have an error but u.Host is still empty, we need
		to prepend the default udp protocol and re-parse the address
	*/
	if u.Host == "" {
		addr = "udp://" + addr
		u2, err := url.Parse(strings.ToLower(addr))
		if err != nil {
			return ds, err
		}
		u = u2
	}

	/*
		Scheme:
		If the scheme is not set, default to 'udp'
		If the scheme is set, but not tcp or udp, error out.
	*/
	switch strings.ToLower(u.Scheme) {
	case "udp", "tcp":
		ds.Protocol = strings.ToLower(u.Scheme)
	default:
		err := fmt.Errorf("invalid protocol specified %s", u.Scheme)
		return ds, err
	}

	// Ensure address is present
	if u.Hostname() == "" {
		return ds, fmt.Errorf("dns server address is mandatory")
	}
	ds.Address = strings.ToLower(u.Hostname())

	// Default port to 53
	ds.Port = 53
	if portStr := u.Port(); portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return ds, fmt.Errorf("invalid port: %v", err)
		}
		ds.Port = port
	}
	ds.URL = addr
	ds.U = u

	return ds, nil
}

type DNSRequest struct {
	Target string
	Server *DNSSvr
}

type DNSResponse struct {
	Answer    []DNSAnswer
	DNSServer string `json:"dns_server"`
	TLS       struct {
		ServerName   string              `json:"server_name"`
		Certificates []*x509.Certificate `json:"certificates"`
	}
}

type DNSAnswer struct {
	Name   string `json:"name"`
	RRType string `json:"rrtype"`
	Value  string `json:"value"`
	TTL    int    `json:"ttl"`
}
