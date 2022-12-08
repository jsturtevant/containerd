/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package server

import (
	"fmt"
	"time"

	wstats "github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/stats"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func createCPUStats(newStats interface{}, timestamp time.Time) (*runtime.CpuUsage, error) {
	switch metrics := newStats.(type) {
	case *wstats.Statistics:
		if metrics != nil {
			wstats := metrics.GetWindows()
			if wstats == nil {
				return nil, fmt.Errorf("windows stats is empty")
			}
			if wstats.Processor != nil {
				return &runtime.CpuUsage{
					Timestamp:            wstats.Timestamp.UnixNano(),
					UsageCoreNanoSeconds: &runtime.UInt64Value{Value: wstats.Processor.TotalRuntimeNS},
				}, nil
			}
		}
	default:
		return nil, fmt.Errorf("unexpected metrics type: %v", metrics)
	}
	return nil, nil
}

func (c *criService) memoryContainerStats(stats interface{}, timestamp time.Time) (*runtime.MemoryUsage, error) {
	switch metrics := stats.(type) {
	case *wstats.Statistics:
		if metrics != nil {
			wstats := metrics.GetWindows()

			if wstats == nil {
				return nil, fmt.Errorf("windows stats is empty")
			}
			if wstats.Memory != nil {
				return &runtime.MemoryUsage{
					Timestamp: wstats.Timestamp.UnixNano(),
					WorkingSetBytes: &runtime.UInt64Value{
						Value: wstats.Memory.MemoryUsagePrivateWorkingSetBytes,
					},
				}, nil
			}
		}
	default:
		return nil, fmt.Errorf("unexpected metrics type: %v", metrics)
	}
	return nil, nil
}
