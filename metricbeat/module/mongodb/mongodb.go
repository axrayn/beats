// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package mongodb

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/elastic/beats/v7/metricbeat/mb/parse"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/x/mongo/driver/connstring"
	mgo "gopkg.in/mgo.v2"
)

func init() {
	// Register the ModuleFactory function for the "mongodb" module.
	if err := mb.Registry.AddModule("mongodb", NewModule); err != nil {
		panic(err)
	}
}

// NewModule creates a new mb.Module instance and validates that at least one host has been
// specified
func NewModule(base mb.BaseModule) (mb.Module, error) {
	// Validate that at least one host has been specified.
	config := struct {
		Hosts []string `config:"hosts"    validate:"nonzero,required"`
	}{}
	if err := base.UnpackConfig(&config); err != nil {
		return nil, err
	}

	return &base, nil
}

// ParseURL parses valid MongoDB URL strings into an mb.HostData instance
func ParseURL(module mb.Module, host string) (mb.HostData, error) {
	c := struct {
		Username string `config:"username"`
		Password string `config:"password"`
	}{}
	if err := module.UnpackConfig(&c); err != nil {
		return mb.HostData{}, err
	}

	if parts := strings.SplitN(host, "://", 2); len(parts) != 2 {
		// Add scheme.
		host = fmt.Sprintf("mongodb://%s", host)
	}

	// This doesn't use URLHostParserBuilder because MongoDB URLs can contain
	// multiple hosts separated by commas (mongodb://host1,host2,host3?options).
	u, err := url.Parse(host)
	if err != nil {
		return mb.HostData{}, fmt.Errorf("error parsing URL: %v", err)
	}

	parse.SetURLUser(u, c.Username, c.Password)

	// https://docs.mongodb.com/manual/reference/connection-string/
	_, err = mgo.ParseURL(u.String())
	if err != nil {
		return mb.HostData{}, err
	}

	return parse.NewHostDataFromURL(u), nil
}

// NewDirectSession estbalishes direct connections with a list of hosts. It uses the supplied
// dialInfo parameter as a template for establishing more direct connections
func NewDirectSession(dialInfo *options.ClientOptions) (*mongo.Client, error) {
	// make a copy
	nodeDialInfo := *dialInfo

	logp.Debug("mongodb", "Connecting to MongoDB node at %v", nodeDialInfo.Hosts)

	client, err := mongo.NewClient(&nodeDialInfo)
	if err != nil {
		logp.Err("Error establishing direct connection to mongo node at %v. Error output: %s", nodeDialInfo.Hosts, err.Error())
		return nil, err
	}

	err = client.Connect(context.Background())
	if err != nil {
		logp.Err("Error establishing direct connection to mongo node at %v. Error output: %s", nodeDialInfo.Hosts, err.Error())
		return nil, err
	}

	return client, nil
}

// SanitiseHost function to remove the username/password options from the host entry
func SanitiseHost(uri string) string {
	if strings.HasPrefix(uri, "mongodb://") && strings.Contains(uri, "@") {
		connStr, err := connstring.Parse(uri)
		if err != nil {
			logp.Err("Cannot parse mongodb server url: %s", err)
			return "unknown/error"
		}

		if connStr.Username != "" {
			uri = strings.Replace(uri, connStr.Username, "****", 1)
		}
		if connStr.Password != "" {
			uri = strings.Replace(uri, connStr.Password, "****", 1)
		}
	}
	return uri
}
