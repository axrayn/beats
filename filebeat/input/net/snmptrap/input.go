package snmptrap

// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     www.apache.org
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

import (
	"net"
	"time"

	"github.com/dustin/go-humanize"

	netinput "github.com/elastic/beats/v7/filebeat/input/net"
	"github.com/elastic/beats/v7/filebeat/input/netmetrics"
	input "github.com/elastic/beats/v7/filebeat/input/v2"
	"github.com/elastic/beats/v7/filebeat/inputsource"
	"github.com/elastic/beats/v7/filebeat/inputsource/snmptrap"
	"github.com/elastic/beats/v7/libbeat/feature"
	"github.com/elastic/beats/v7/libbeat/management/status"
	conf "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/monitoring"
	"github.com/elastic/go-concert/ctxtool"
)

// Plugin returns the input plugin definition for snmptrap.
func Plugin() input.Plugin {
	return input.Plugin{
		Name:       "snmptrap",
		Stability:  feature.Stable,
		Deprecated: false,
		Info:       "SNMP trap server",
		Manager:    netinput.NewManager(configure),
	}
}

func configure(cfg *conf.C) (netinput.Input, error) {
	config := defaultConfig()
	if err := cfg.Unpack(&config); err != nil {
		return nil, err
	}

	return newServer(config)
}

func defaultConfig() config {
	return config{
		Config: snmptrap.Config{
			MaxMessageSize: 10 * humanize.KiByte,
			Host:           "localhost:162", // Standard trap port
			Timeout:        time.Minute * 5,
			// Default community for testing/standard use
			CommunityStrings: []string{"public"},
			EngineID:         "0x80001f88800a0462333f24236900000000",
		},
	}
}

type server struct {
	// Embed the inputsource configuration structure
	config
	metrics    *netmetrics.UDP  // Metrics generally reuse UDP counters for traps
	trapServer *snmptrap.Server // The actual listener instance
}

// config embeds the inputsource config inline
type config struct {
	snmptrap.Config `config:",inline"`
}

func newServer(config config) (*server, error) {
	s := &server{
		config: config,
	}
	return s, nil
}

func (s *server) Name() string { return "snmptrap" }

// Test ensures we can bind to the configured host and port.
func (s *server) Test(_ input.TestContext) error {
	l, err := net.Listen("udp", s.Host)
	if err != nil {
		return err
	}
	return l.Close()
}

func (s *server) InitMetrics(id string, reg *monitoring.Registry, logger *logp.Logger) netinput.Metrics {
	// We use the UDP metrics structure as traps are sent over UDP
	s.metrics = netmetrics.NewUDP(reg, s.Host, uint64(s.MaxMessageSize), time.Second, logger)
	return s.metrics
}

func (s *server) Run(ctx input.Context, evtChan chan<- netinput.DataMetadata, metrics netinput.Metrics) (err error) {
	logger := ctx.Logger
	defer s.metrics.Close()

	// The inputsource/snmptrap/server.go's handlePDU now marshals data to JSON bytes
	// which are passed into this callback function as `data`.
	callback := func(data []byte, metadata inputsource.NetworkMetadata) {
		now := time.Now()
		metrics.EventReceived(len(data), now)

		logger.Debugw(
			"SNMP Trap (JSON) processed",
			"bytes", len(data),
			"remote_address", metadata.RemoteAddr.String())

		evtChan <- netinput.DataMetadata{
			Data:      data, // The JSON payload byte array
			Metadata:  metadata,
			Timestamp: now,
		}
	}

	// Initialize the actual listener server
	s.trapServer = snmptrap.New(&s.Config, callback, logger)

	logger.Debug("SNMP Trap input initialized")
	ctx.UpdateStatus(status.Running, "")

	// Run the server using the cancellation context
	return s.trapServer.Run(ctxtool.FromCanceller(ctx.Cancelation))
}
