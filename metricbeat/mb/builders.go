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

package mb

import (
	"errors"
	"fmt"
	"strings"

	"github.com/gofrs/uuid/v5"
	"github.com/joeshaw/multierror"

	conf "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/monitoring"
)

var (
	// ErrEmptyConfig indicates that modules configuration list is nil or empty.
	ErrEmptyConfig = errors.New("one or more modules must be configured")

	// ErrAllModulesDisabled indicates that all modules are disabled. At least
	// one module must be enabled.
	ErrAllModulesDisabled = errors.New("all modules are disabled")

	// ErrModuleDisabled indicates a disabled module has been tried to instantiate.
	ErrModuleDisabled = errors.New("disabled module")
)

// NewModule builds a new Module and its associated MetricSets based on the
// provided configuration data. config contains config data (the data
// will be unpacked into ModuleConfig structs). r is the Register where the
// ModuleFactory's and MetricSetFactory's will be obtained from. This method
// returns a Module and its configured MetricSets or an error.
func NewModule(config *conf.C, r *Register, logger *logp.Logger) (Module, []MetricSet, error) {
	if !config.Enabled() {
		return nil, nil, ErrModuleDisabled
	}

	bm, err := newBaseModuleFromConfig(config, logger)
	if err != nil {
		return nil, nil, err
	}

	module, err := createModule(r, bm)
	if err != nil {
		return nil, nil, err
	}

	metricsets, err := initMetricSets(r, module, logger)
	if err != nil {
		return nil, nil, err
	}

	return module, metricsets, nil
}

// newBaseModuleFromConfig creates a new BaseModule from config. The returned
// BaseModule's name will always be lower case.
func newBaseModuleFromConfig(rawConfig *conf.C, logger *logp.Logger) (BaseModule, error) {
	baseModule := BaseModule{
		config:    DefaultModuleConfig(),
		rawConfig: rawConfig,
		Logger:    logger,
	}
	err := rawConfig.Unpack(&baseModule.config)
	if err != nil {
		return baseModule, err
	}

	// If timeout is not set, timeout is set to the same value as period
	if baseModule.config.Timeout == 0 {
		baseModule.config.Timeout = baseModule.config.Period
	}

	baseModule.name = strings.ToLower(baseModule.config.Module)

	err = mustNotContainDuplicates(baseModule.config.Hosts)
	if err != nil {
		return baseModule, fmt.Errorf("invalid hosts for module '%s': %w", baseModule.name, err)
	}

	return baseModule, nil
}

func createModule(r *Register, bm BaseModule) (Module, error) {
	f := r.moduleFactory(bm.Name())
	if f == nil {
		f = DefaultModuleFactory
	}

	return f(bm)
}

func initMetricSets(r *Register, m Module, logger *logp.Logger) ([]MetricSet, error) {
	var (
		errs multierror.Errors
	)

	bms, err := newBaseMetricSets(r, m, logger)
	if err != nil {
		return nil, err
	}

	metricsets := make([]MetricSet, 0, len(bms))
	for _, bm := range bms {
		registration, err := r.metricSetRegistration(bm.Module().Name(), bm.Name())
		if err != nil {
			errs = append(errs, err)
			continue
		}

		bm.registration = registration
		bm.hostData = HostData{URI: bm.host}
		if registration.HostParser != nil {
			bm.hostData, err = registration.HostParser(bm.Module(), bm.host)
			if err != nil {
				errs = append(errs, fmt.Errorf("host parsing failed for %v-%v: %w",
					bm.Module().Name(), bm.Name(), err))
				continue
			}
			bm.host = bm.hostData.Host
		}

		metricSet, err := registration.Factory(bm)
		if err == nil {
			err = mustHaveModule(metricSet, bm)
			if err == nil {
				err = mustImplementFetcher(metricSet)
			}
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}

		metricsets = append(metricsets, metricSet)
	}

	return metricsets, errs.Err()
}

// newBaseMetricSets creates a new BaseMetricSet for all MetricSets defined
// in the module's config. An error is returned if no MetricSets are specified
// in the module's config and no default MetricSet is defined.
func newBaseMetricSets(r *Register, m Module, logger *logp.Logger) ([]BaseMetricSet, error) {
	hosts := []string{""}
	if l := m.Config().Hosts; len(l) > 0 {
		hosts = l
	}

	metricSetNames := m.Config().MetricSets
	if len(metricSetNames) == 0 {
		var err error
		metricSetNames, err = r.DefaultMetricSets(m.Name())
		if err != nil {
			return nil, fmt.Errorf("no metricsets configured for module '%s'", m.Name())
		}
	}

	var metricsets []BaseMetricSet
	for _, name := range metricSetNames {
		name = strings.ToLower(name)
		for _, host := range hosts {
			id, err := uuid.NewV4()
			if err != nil {
				return nil, fmt.Errorf("failed to generate ID for metricset: %w", err)
			}
			msID := id.String()
			metrics := monitoring.NewRegistry()
			monitoring.NewString(metrics, "input").Set(m.Name() + "/" + name)
			if host != "" {
				monitoring.NewString(metrics, "host").Set(host)
			}
			monitoring.NewString(metrics, "ephemeral_id").Set(msID)
			if configuredID := m.Config().ID; configuredID != "" {
				// If a module ID was configured, then use that as the ID within metrics.
				// Note that the "ephemeral_id" is what is used as the monitoring registry
				// key. This module ID is not unique to the MetricSet instance when multiple
				// hosts are monitored or if multiple different MetricSet types were enabled
				// under the same module instance.
				monitoring.NewString(metrics, "id").Set(configuredID)
			} else {
				monitoring.NewString(metrics, "id").Set(msID)
			}

			logger := logger.Named(m.Name() + "." + name)
			if m.Config().ID != "" {
				logger = logger.With("id", m.Config().ID)
			}
			metricsets = append(metricsets, BaseMetricSet{
				id:      msID,
				name:    name,
				module:  m,
				host:    host,
				metrics: metrics,
				logger:  logger,
			})
		}
	}
	return metricsets, nil
}

// mustHaveModule returns an error if the given MetricSet's Module() method
// returns nil. This validation ensures that all MetricSet implementations
// honor the interface contract.
func mustHaveModule(ms MetricSet, base BaseMetricSet) error {
	if ms.Module() == nil {
		return fmt.Errorf("%s module cannot be nil in %T", base.module.Name(), ms)
	}
	return nil
}

// mustImplementFetcher returns an error if the given MetricSet does not
// implement one of the Fetcher interface or if it implements more than one
// of them.
func mustImplementFetcher(ms MetricSet) error {
	var ifcs []string
	if _, ok := ms.(ReportingMetricSet); ok {
		ifcs = append(ifcs, "ReportingMetricSet")
	}

	if _, ok := ms.(PushMetricSet); ok {
		ifcs = append(ifcs, "PushMetricSet")
	}

	if _, ok := ms.(ReportingMetricSetV2); ok {
		ifcs = append(ifcs, "ReportingMetricSetV2")
	}

	if _, ok := ms.(ReportingMetricSetV2Error); ok {
		ifcs = append(ifcs, "ReportingMetricSetV2Error")
	}

	if _, ok := ms.(ReportingMetricSetV2WithContext); ok {
		ifcs = append(ifcs, "ReportingMetricSetV2WithContext")
	}

	if _, ok := ms.(PushMetricSetV2); ok {
		ifcs = append(ifcs, "PushMetricSetV2")
	}

	if _, ok := ms.(PushMetricSetV2WithContext); ok {
		ifcs = append(ifcs, "PushMetricSetV2WithContext")
	}

	switch len(ifcs) {
	case 0:
		return fmt.Errorf("MetricSet '%s/%s' does not implement an event "+
			"producing interface ("+
			"ReportingMetricSet, ReportingMetricSetV2, ReportingMetricSetV2Error, ReportingMetricSetV2WithContext"+
			"PushMetricSet, PushMetricSetV2, or PushMetricSetV2WithContext)",
			ms.Module().Name(), ms.Name())
	case 1:
		return nil
	default:
		return fmt.Errorf("MetricSet '%s/%s' can only implement a single "+
			"event producing interface, but implements %v", ms.Module().Name(),
			ms.Name(), ifcs)
	}
}

// mustNotContainDuplicates returns an error if the given slice contains
// duplicate values.
func mustNotContainDuplicates(s []string) error {
	duplicates := map[string]struct{}{}
	set := make(map[string]struct{}, len(s))
	for _, v := range s {
		_, encountered := set[v]
		if encountered {
			duplicates[v] = struct{}{}
			continue
		}
		set[v] = struct{}{}
	}

	if len(duplicates) > 0 {
		var keys []string
		for dup := range duplicates {
			keys = append(keys, dup)
		}
		return fmt.Errorf("duplicates detected [%s]", strings.Join(keys, ", "))
	}

	return nil
}
