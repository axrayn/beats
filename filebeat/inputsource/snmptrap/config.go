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

package snmptrap

import (
	"errors"
	"fmt"
	"time"

	"github.com/elastic/beats/v7/libbeat/common/cfgtype"
)

// Define network constants
const (
	networkUDP  = "udp"
	networkUDP4 = "udp4"
	networkUDP6 = "udp6"
)

var ErrInvalidNetwork = errors.New("invalid network value")

// V3User defines the configuration required for SNMPv3 security.
type V3User struct {
	Username     string `config:"username" validate:"required"`
	AuthProtocol string `config:"auth_protocol"` // e.g., "SHA", "MD5", ""
	AuthPass     string `config:"auth_pass"`
	PrivProtocol string `config:"priv_protocol"` // e.g., "AES", "DES", ""
	PrivPass     string `config:"priv_pass"`
	EngineID     string `config:"engine_id"`
}

// Config options for the SNMPTrap Server
type Config struct {
	Host           string           `config:"host" validate:"required"`
	MaxMessageSize cfgtype.ByteSize `config:"max_message_size" validate:"positive,nonzero"`
	Timeout        time.Duration    `config:"timeout"`
	Network        string           `config:"network"`

	// SNMP Specific fields
	EngineID         string            `config:"engine_id"`
	CommunityStrings []string          `config:"community_strings"`
	V3Users          map[string]V3User `config:"v3_users"`
}

// Validate validates the Config option for the snmptrap input.
func (c *Config) Validate() error {
	switch c.Network {
	case "", networkUDP, networkUDP4, networkUDP6:
	default:
		return fmt.Errorf("%w: %s, expected: %v or %v or %v", ErrInvalidNetwork, c.Network, networkUDP, networkUDP4, networkUDP6)
	}

	if len(c.CommunityStrings) == 0 && len(c.V3Users) == 0 {
		return errors.New("at least one community string or v3 user must be defined")
	}

	return nil
}
