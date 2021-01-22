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

package host

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/pkg/errors"

	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/metricbeat/mb"

	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/view"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
)

func init() {
	mb.Registry.MustAddMetricSet("vsphere", "host", New,
		mb.DefaultMetricSet(),
	)
}

// MetricSet type defines all fields of the MetricSet
type MetricSet struct {
	mb.BaseMetricSet
	HostURL  *url.URL
	Insecure bool
}

// New create a new instance of the MetricSet
func New(base mb.BaseMetricSet) (mb.MetricSet, error) {
	config := struct {
		Username string `config:"username"`
		Password string `config:"password"`
		Insecure bool   `config:"insecure"`
	}{}

	if err := base.Module().UnpackConfig(&config); err != nil {
		return nil, err
	}

	u, err := url.Parse(base.HostData().URI)
	if err != nil {
		return nil, err
	}

	u.User = url.UserPassword(config.Username, config.Password)

	return &MetricSet{
		BaseMetricSet: base,
		HostURL:       u,
		Insecure:      config.Insecure,
	}, nil
}

// Fetch methods implements the data gathering and data conversion to the right
// format. It publishes the event which is then forwarded to the output. In case
// of an error set the Error field of mb.Event or simply call report.Error().
func (m *MetricSet) Fetch(ctx context.Context, reporter mb.ReporterV2) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	client, err := govmomi.NewClient(ctx, m.HostURL, m.Insecure)
	if err != nil {
		return errors.Wrap(err, "error in NewClient")
	}

	defer func() {
		if err := client.Logout(ctx); err != nil {
			m.Logger().Debug(errors.Wrap(err, "error trying to logout from vshphere"))
		}
	}()

	c := client.Client

	// Create a view of HostSystem objects.
	mgr := view.NewManager(c)

	v, err := mgr.CreateContainerView(ctx, c.ServiceContent.RootFolder, []string{"HostSystem"}, true)
	if err != nil {
		return errors.Wrap(err, "error in CreateContainerView")
	}

	defer func() {
		if err := v.Destroy(ctx); err != nil {
			m.Logger().Debug(errors.Wrap(err, "error trying to destroy view from vshphere"))
		}
	}()

	// Retrieve summary property for all hosts.
	var hst []mo.HostSystem
	err = v.Retrieve(ctx, []string{"HostSystem"}, []string{"summary"}, &hst)
	if err != nil {
		return errors.Wrap(err, "error in Retrieve")
	}

	for _, hs := range hst {

		event := common.MapStr{}

		event["name"] = hs.Summary.Config.Name
		event.Put("cpu.used.mhz", hs.Summary.QuickStats.OverallCpuUsage)
		event.Put("memory.used.bytes", int64(hs.Summary.QuickStats.OverallMemoryUsage)*1024*1024)
                event.Put("overall.status", hs.Summary.OverallStatus)
                event.Put("reboot.required", hs.Summary.RebootRequired)
                event.Put("product.name", hs.Summary.Config.Product.Name)
                event.Put("product.version", hs.Summary.Config.Product.Version)
                event.Put("product.build", hs.Summary.Config.Product.Build)
                event.Put("vmotion.enabled", hs.Summary.Config.VmotionEnabled)


		if hs.Summary.Hardware != nil {
			totalCPU := int64(hs.Summary.Hardware.CpuMhz) * int64(hs.Summary.Hardware.NumCpuCores)
			event.Put("cpu.total.mhz", totalCPU)
			event.Put("cpu.free.mhz", int64(totalCPU)-int64(hs.Summary.QuickStats.OverallCpuUsage))
			event.Put("memory.free.bytes", int64(hs.Summary.Hardware.MemorySize)-(int64(hs.Summary.QuickStats.OverallMemoryUsage)*1024*1024))
			event.Put("memory.total.bytes", hs.Summary.Hardware.MemorySize)
                        event.Put("hardware.vendor", hs.Summary.Hardware.Vendor)
                        event.Put("hardware.model", hs.Summary.Hardware.Model)
                        event.Put("hardware.cpu.model", hs.Summary.Hardware.CpuModel)
                        event.Put("hardware.cpu.pkgs", int64(hs.Summary.Hardware.NumCpuPkgs))
                        event.Put("hardware.cpu.cores", int64(hs.Summary.Hardware.NumCpuCores))
                        event.Put("hardware.cpu.threads", int64(hs.Summary.Hardware.NumCpuThreads))
                        event.Put("hardware.nics", int64(hs.Summary.Hardware.NumNics))
                        event.Put("hardware.hbas", int64(hs.Summary.Hardware.NumHBAs))

		} else {
			m.Logger().Debug("'Hardware' or 'Summary' data not found. This is either a parsing error from vsphere library, an error trying to reach host/guest or incomplete information returned from host/guest")
		}

		if hs.Summary.Host != nil {
			networkNames, err := getNetworkNames(ctx, c, hs.Summary.Host.Reference())
			if err != nil {
				m.Logger().Debugf("error trying to get network names: %s", err.Error())
			} else {
				if len(networkNames) > 0 {
					event["network_names"] = networkNames
				}
			}
		}
                if hs.Summary.Runtime != nil {
                    event.Put("runtime.connection_state", hs.Summary.Runtime.ConnectionState)
                    event.Put("runtime.power_state", hs.Summary.Runtime.PowerState)
                    event.Put("runtime.standby_mode", hs.Summary.Runtime.StandbyMode)
                    event.Put("runtime.maintenance_mode", hs.Summary.Runtime.InMaintenanceMode)
                    event.Put("runtime.quarantine_mode", hs.Summary.Runtime.InQuarantineMode)
                    event.Put("runtime.boottime", hs.Summary.Runtime.BootTime)
                }
		reporter.Event(mb.Event{
			MetricSetFields: event,
		})
	}

	return nil
}

func getNetworkNames(ctx context.Context, c *vim25.Client, ref types.ManagedObjectReference) ([]string, error) {
	var outputNetworkNames []string

	pc := property.DefaultCollector(c)

	var hs mo.HostSystem
	err := pc.RetrieveOne(ctx, ref, []string{"network"}, &hs)
	if err != nil {
		return nil, fmt.Errorf("error retrieving host information: %v", err)
	}

	if len(hs.Network) == 0 {
		return nil, errors.New("no networks found")
	}

	var networkRefs []types.ManagedObjectReference
	for _, obj := range hs.Network {
		if obj.Type == "Network" {
			networkRefs = append(networkRefs, obj)
		}
	}

	if len(networkRefs) == 0 {
		return nil, errors.New("no networks found")
	}

	var nets []mo.Network
	err = pc.Retrieve(ctx, networkRefs, []string{"name"}, &nets)
	if err != nil {
		return nil, fmt.Errorf("error retrieving network from host: %v", err)
	}

	for _, net := range nets {
		name := strings.Replace(net.Name, ".", "_", -1)
		outputNetworkNames = append(outputNetworkNames, name)
	}

	return outputNetworkNames, nil
}
