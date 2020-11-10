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
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"

	"github.com/elastic/beats/v7/libbeat/common/transport/tlscommon"
	"github.com/elastic/beats/v7/metricbeat/mb"
)

// ModuleConfig contains the common configuration for this module
type ModuleConfig struct {
	TLS *tlscommon.Config `config:"ssl"`
}

// MetricSet type defines all fields of the MetricSet
type MetricSet struct {
	mb.BaseMetricSet
	ClientOptions *options.ClientOptions
}

// NewMetricSet creates a new instance of the MetricSet
func NewMetricSet(base mb.BaseMetricSet) (*MetricSet, error) {
	var config ModuleConfig
	err := base.Module().UnpackConfig(&config)
	if err != nil {
		return nil, err
	}

	dialInfo := options.Client().ApplyURI(base.HostData().URI)
	if err != nil {
		return nil, err
	}
	dialInfo.SetConnectTimeout(base.Module().Config().Timeout)
	dialInfo.SetDirect(false)
	dialInfo.SetReadPreference(readpref.Nearest())
	dialInfo.SetAppName("metricbeat")

	return &MetricSet{
		BaseMetricSet: base,
		ClientOptions: dialInfo,
	}, nil
}
