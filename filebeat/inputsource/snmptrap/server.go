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
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/elastic/beats/v7/filebeat/inputsource"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/gosnmp/gosnmp"
)

// Name is the human readable name and identifier.
const Name = "snmptrap"

// Hack to get gosnmp to be happy with logp not having a Printf method
type gosnmpLogger struct {
	logger *logp.Logger
}

func (l *gosnmpLogger) Print(v ...interface{}) {
	l.logger.Info(fmt.Sprint(v...))
}

func (l *gosnmpLogger) Printf(format string, v ...interface{}) {
	l.logger.Infof(format, v...)
}

func (l *gosnmpLogger) Println(v ...interface{}) {
	l.logger.Info(fmt.Sprintln(v...))
}

func (l *gosnmpLogger) Write(p []byte) (n int, err error) {
	msg := strings.TrimSpace(string(p))
	if msg != "" {
		l.logger.Info(msg)
	}
	return len(p), nil
}

// Server creates a SNMP Trap listener.
type Server struct {
	config   *Config
	logger   *logp.Logger
	slogger  *gosnmp.Logger
	listener *gosnmp.TrapListener
	callback inputsource.NetworkFunc

	// SNMP specific fields derived from config
	communityMap  map[string]bool
	v3UserManager *gosnmp.GoSNMP
}

// Struct to match the required JSON output format
type TrapMessage struct {
	Timestamp    string             `json:"timestamp"`
	Sender       string             `json:"sender"`
	Version      string             `json:"version"`
	Community    string             `json:"community,omitempty"`
	TrapOID      string             `json:"trap_oid,omitempty"`
	Enterprise   string             `json:"enterprise,omitempty"`
	GenericTrap  *int               `json:"generic_trap,omitempty"`
	SpecificTrap *int               `json:"specific_trap,omitempty"`
	VarBinds     map[string]VarBind `json:"varbinds"`
}

// Helper struct for VarBinds
type VarBind struct {
	OID   string      `json:"oid"`
	Type  string      `json:"type"`
	Value interface{} `json:"value"`
}

func parseVersion(ver gosnmp.SnmpVersion) string {
	switch ver {
	case gosnmp.Version1:
		return "v1"
	case gosnmp.Version2c:
		return "v2c"
	case gosnmp.Version3:
		return "v3"
	default:
		return "unknown"
	}
}

func parseAuthProto(authproto string) gosnmp.SnmpV3AuthProtocol {
	s := strings.ToLower(authproto)
	switch s {
	case "sha", "sha1":
		return gosnmp.SHA
	case "md5":
		return gosnmp.MD5
	case "sha224":
		return gosnmp.SHA224
	case "sha256":
		return gosnmp.SHA256
	case "sha384":
		return gosnmp.SHA384
	case "sha512":
		return gosnmp.SHA512
	case "noauth", "none", "":
		return gosnmp.NoAuth
	default:
		return gosnmp.NoAuth
	}
}

func parsePrivProto(privproto string) gosnmp.SnmpV3PrivProtocol {
	s := strings.ToLower(privproto)
	switch s {
	case "des":
		return gosnmp.DES
	case "aes", "aes128":
		return gosnmp.AES
	case "aes192":
		return gosnmp.AES192
	case "aes256":
		return gosnmp.AES256
	case "aes192c":
		return gosnmp.AES192C
	case "aes256c":
		return gosnmp.AES256C
	case "nopriv", "none", "":
		return gosnmp.NoPriv
	default:
		return gosnmp.NoPriv
	}
}

// New returns a new SNMPTrap Server instance.
func New(config *Config, callback inputsource.NetworkFunc, logger *logp.Logger) *Server {
	s := &Server{
		config:       config,
		logger:       logger,
		callback:     callback,
		communityMap: make(map[string]bool),
	}

	// Prepare community strings map
	for _, comm := range config.CommunityStrings {
		s.communityMap[comm] = true
	}

	// Build the fake gosnmp Logger
	//adapter := &gosnmpLogger{logger: logger}
	gsLogger := gosnmp.NewLogger(nil)

	// Prepare V3 Users manager
	s.v3UserManager = &gosnmp.GoSNMP{}
	params := &gosnmp.GoSNMP{
		SecurityModel: gosnmp.UserSecurityModel,
		Logger:        gosnmp.NewLogger(s.slogger),
	}
	s.v3UserManager.SecurityParameters = params.SecurityParameters

	// Build SNMPv3 security parameters table and populate it
	usmTable := gosnmp.NewSnmpV3SecurityParametersTable(gsLogger)
	for _, u := range config.V3Users {
		s.logger.Infof("Adding v3 user %s", u.Username)
		var eid []byte
		if u.EngineID != "" {
			s := strings.TrimPrefix(u.EngineID, "0x")
			if b, err := hex.DecodeString(s); err == nil {
				eid = b
			} else {
				eid = []byte(u.EngineID)
			}
		}

		sp := &gosnmp.UsmSecurityParameters{
			UserName:                 u.Username,
			AuthenticationPassphrase: u.AuthPass,
			AuthenticationProtocol:   parseAuthProto(u.AuthProtocol),
			PrivacyPassphrase:        u.PrivPass,
			PrivacyProtocol:          parsePrivProto(u.PrivProtocol),
			AuthoritativeEngineID:    string(eid),
		}

		if err := usmTable.Add(u.Username, sp); err != nil {
			usmTable.Logger.Print(err)
		}
		// also add by engineid string key so lookups by engineid (if used) can find it
		if len(eid) > 0 {
			k := fmt.Sprintf("0x%x", eid)
			if err := usmTable.Add(k, sp); err != nil {
				s.logger.Errorf("Error adding v3 user %s", err)
			}
		}
	}

	s.listener = gosnmp.NewTrapListener()
	gsParams := &gosnmp.GoSNMP{
		SecurityModel:               gosnmp.UserSecurityModel,
		Logger:                      gsLogger,
		Version:                     gosnmp.Version3,
		TrapSecurityParametersTable: usmTable,
	}
	s.listener.Params = gsParams

	s.slogger = &gsLogger
	secparam := &gosnmp.UsmSecurityParameters{
		AuthoritativeEngineID: config.EngineID,
	}
	s.listener.Params.SecurityParameters = (secparam)

	s.listener.OnNewTrap = s.handleTrap

	return s
}

// Run starts the SNMP Trap server. This method blocks until the context is cancelled or an error occurs.
func (s *Server) Run(ctx context.Context) error {
	addr := s.config.Host
	s.logger.Infof("Starting SNMP trap listener on %s (%s)", addr, s.config.Network)
	s.logger.Infof("Working with config %+v", s.config)

	// The listener.Listen function takes an address string and blocks.
	// We use the context to manage the lifecycle and eventual closing of the listener.

	errChan := make(chan error, 1)

	go func() {
		errChan <- s.listener.Listen(addr)
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("SNMP server shutting down due to context cancellation.")
		s.listener.Close()
		return ctx.Err()
	case err := <-errChan:
		s.listener.Close()
		return err
	}
}

func (s *Server) network() string {
	if s.config.Network != "" {
		return s.config.Network
	}
	return networkUDP
}

func (s *Server) validateCommunity(community string) bool {
	_, ok := s.communityMap[community]
	return ok
}

// handleTrap is the entry point for all traps received by the listener.
func (s *Server) handleTrap(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
	// first validate the community string for v1/v2c
	if (packet.Version == gosnmp.Version1 || packet.Version == gosnmp.Version2c) && !s.validateCommunity(packet.Community) {
		s.logger.Errorf("Rejected SNMP packet from %s with invalid community string", addr.String())
		return
	}

	if packet.Version == gosnmp.Version3 {
		s.logger.Infof("Received an SNMPv3 trap message from %s", addr.String())
	}
	trapMsg := s.transformPacketToTrapMessage(packet, (addr), packet.Community)
	// Convert the structured message to bytes (JSON)
	data, err := json.Marshal(trapMsg)
	if err != nil {
		s.logger.Errorw("Failed to marshal SNMP trap message to JSON", "error", err)
		return
	}
	nm := inputsource.NetworkMetadata{
		RemoteAddr: addr,
		Truncated:  false,
	}
	// Invoke the callback with the JSON data

	s.callback(data, nm)

}

// transformPacketToTrapMessage converts a gosnmp.SnmpPacket into the required JSON structure
func (s *Server) transformPacketToTrapMessage(packet *gosnmp.SnmpPacket, sender net.Addr, community string) TrapMessage {
	versionStr := parseVersion(packet.Version)

	trapMsg := TrapMessage{
		Timestamp: time.Now().Format(time.RFC3339),
		Sender:    sender.String(),
		Version:   versionStr,
		Community: community,
		VarBinds:  make(map[string]VarBind),
	}

	// Specific V1 fields
	//if packet.Version == gosnmp.Version1 {
	//	trapMsg.Enterprise = packet.Enterprise
	generic := int(packet.GenericTrap)
	specific := int(packet.SpecificTrap)
	trapMsg.GenericTrap = &generic
	trapMsg.SpecificTrap = &specific
	//} else {
	// V2/V3 look for specific OIDs to find the standard trap OID
	for _, v := range packet.Variables {
		if v.Name == "1.3.6.1.6.3.1.1.4.1.0" { // snmpTrapOID.0
			if oidVal, ok := v.Value.(string); ok {
				trapMsg.TrapOID = oidVal
			}
			break
		}
	}
	//}

	for _, v := range packet.Variables {
		bind := VarBind{
			OID:   v.Name,
			Type:  v.Type.String(),
			Value: v.Value,
		}
		trapMsg.VarBinds[v.Name] = bind
	}

	return trapMsg
}
