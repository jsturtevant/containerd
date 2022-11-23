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
	"context"
	"fmt"
	wstats "github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/stats"
	"github.com/containerd/containerd/api/types"
	containerstore "github.com/containerd/containerd/pkg/cri/store/container"
	"github.com/containerd/containerd/pkg/cri/store/stats"
	"github.com/containerd/containerd/protobuf"
	"github.com/containerd/typeurl"
	"time"

	tasks "github.com/containerd/containerd/api/services/tasks/v1"
	v1 "github.com/containerd/containerd/metrics/types/v1"
	v2 "github.com/containerd/containerd/metrics/types/v2"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// ContainerStats returns stats of the container. If the container does not
// exist, the call returns an error.
func (c *criService) ContainerStats(ctx context.Context, in *runtime.ContainerStatsRequest) (*runtime.ContainerStatsResponse, error) {
	cntr, err := c.containerStore.Get(in.GetContainerId())
	if err != nil {
		return nil, fmt.Errorf("failed to find container: %w", err)
	}
	request := &tasks.MetricsRequest{Filters: []string{"id==" + cntr.ID}}
	resp, err := c.client.TaskService().Metrics(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metrics for task: %w", err)
	}
	if len(resp.Metrics) != 1 {
		return nil, fmt.Errorf("unexpected metrics response: %+v", resp.Metrics)
	}

	cs, err := c.containerMetrics(cntr, resp.Metrics[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode container metrics: %w", err)
	}

	// save updated metrics in the cache
	err = c.saveContainerMetrics(cntr.ID, cs)
	if err != nil {
		return nil, fmt.Errorf("failed to update container stats ID: %s: %w", cntr.Metadata.ID, err)
	}

	return &runtime.ContainerStatsResponse{Stats: cs}, nil
}

func (c *criService) saveContainerMetrics(cntrID string, cs *runtime.ContainerStats) error {
	// we may not have stats since container hasn't started yet so skip saving to cache
	if cs == nil || cs.Cpu == nil || cs.Cpu.UsageCoreNanoSeconds == nil {
		return nil
	}

	newStats := &stats.ContainerStats{
		UsageCoreNanoSeconds: cs.Cpu.UsageNanoCores.Value,
		Timestamp:            time.Unix(0, cs.Cpu.Timestamp),
	}
	return c.containerStore.UpdateContainerStats(cntrID, newStats)
}

func (c *criService) containerMetrics(
	container containerstore.Container,
	stats *types.Metric,
) (*runtime.ContainerStats, error) {
	var cs runtime.ContainerStats
	var usedBytes, inodesUsed uint64
	sn, err := c.snapshotStore.Get(container.ID)
	// If snapshotstore doesn't have cached snapshot information
	// set WritableLayer usage to zero
	if err == nil {
		usedBytes = sn.Size
		inodesUsed = sn.Inodes
	}
	cs.WritableLayer = &runtime.FilesystemUsage{
		Timestamp: sn.Timestamp,
		FsId: &runtime.FilesystemIdentifier{
			Mountpoint: c.imageFSPath,
		},
		UsedBytes:  &runtime.UInt64Value{Value: usedBytes},
		InodesUsed: &runtime.UInt64Value{Value: inodesUsed},
	}
	cs.Attributes = &runtime.ContainerAttributes{
		Id:          container.ID,
		Metadata:    container.Config.GetMetadata(),
		Labels:      container.Config.GetLabels(),
		Annotations: container.Config.GetAnnotations(),
	}

	if stats != nil {
		s, err := typeurl.UnmarshalAny(stats.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to extract container metrics: %w", err)
		}

		cpuStats, err := c.cpuContainerStats(container.Stats, s, protobuf.FromTimestamp(stats.Timestamp))
		if err != nil {
			return nil, fmt.Errorf("failed to obtain cpu stats: %w", err)
		}
		cs.Cpu = cpuStats

		memoryStats, err := c.memoryContainerStats(s, protobuf.FromTimestamp(stats.Timestamp))
		if err != nil {
			return nil, fmt.Errorf("failed to obtain memory stats: %w", err)
		}
		cs.Memory = memoryStats
	}

	return &cs, nil
}

// getWorkingSet calculates workingset memory from cgroup memory stats.
// The caller should make sure memory is not nil.
// workingset = usage - total_inactive_file
func getWorkingSet(memory *v1.MemoryStat) uint64 {
	if memory.Usage == nil {
		return 0
	}
	var workingSet uint64
	if memory.TotalInactiveFile < memory.Usage.Usage {
		workingSet = memory.Usage.Usage - memory.TotalInactiveFile
	}
	return workingSet
}

// getWorkingSetV2 calculates workingset memory from cgroupv2 memory stats.
// The caller should make sure memory is not nil.
// workingset = usage - inactive_file
func getWorkingSetV2(memory *v2.MemoryStat) uint64 {
	var workingSet uint64
	if memory.InactiveFile < memory.Usage {
		workingSet = memory.Usage - memory.InactiveFile
	}
	return workingSet
}

func isMemoryUnlimited(v uint64) bool {
	// Size after which we consider memory to be "unlimited". This is not
	// MaxInt64 due to rounding by the kernel.
	// TODO: k8s or cadvisor should export this https://github.com/google/cadvisor/blob/2b6fbacac7598e0140b5bc8428e3bdd7d86cf5b9/metrics/prometheus.go#L1969-L1971
	const maxMemorySize = uint64(1 << 62)

	return v > maxMemorySize
}

// https://github.com/kubernetes/kubernetes/blob/b47f8263e18c7b13dba33fba23187e5e0477cdbd/pkg/kubelet/stats/helper.go#L68-L71
func getAvailableBytes(memory *v1.MemoryStat, workingSetBytes uint64) uint64 {
	// memory limit - working set bytes
	if !isMemoryUnlimited(memory.Usage.Limit) {
		return memory.Usage.Limit - workingSetBytes
	}
	return 0
}

func getAvailableBytesV2(memory *v2.MemoryStat, workingSetBytes uint64) uint64 {
	// memory limit (memory.max) for cgroupv2 - working set bytes
	if !isMemoryUnlimited(memory.UsageLimit) {
		return memory.UsageLimit - workingSetBytes
	}
	return 0
}

func (c *criService) cpuContainerStats(oldStats *stats.ContainerStats, newStats interface{}, timestamp time.Time) (*runtime.CpuUsage, error) {
	cpuUsage := &runtime.CpuUsage{}
	switch metrics := newStats.(type) {
	case *v1.Metrics:
		if metrics.CPU != nil && metrics.CPU.Usage != nil {
			cpuUsage.Timestamp = timestamp.UnixNano()
			cpuUsage.UsageCoreNanoSeconds = &runtime.UInt64Value{Value: metrics.CPU.Usage.Total}
		}
	case *v2.Metrics:
		if metrics.CPU != nil {
			// convert to nano seconds
			usageCoreNanoSeconds := metrics.CPU.UsageUsec * 1000
			cpuUsage.Timestamp = timestamp.UnixNano()
			cpuUsage.UsageCoreNanoSeconds = &runtime.UInt64Value{Value: usageCoreNanoSeconds}
		}
	case *wstats.Statistics:
		if metrics != nil {
			wstats := metrics.GetWindows()
			if wstats == nil {
				return nil, fmt.Errorf("windows stats is empty")
			}
			if wstats.Processor != nil {
				cpuUsage.Timestamp = wstats.Timestamp.UnixNano()
				cpuUsage.UsageCoreNanoSeconds = &runtime.UInt64Value{Value: wstats.Processor.TotalRuntimeNS}
			}
		}
	default:
		return nil, fmt.Errorf("unexpected metrics type: %v", metrics)
	}

	// this is a calculated value and should be computed for all OSes
	// UsageCoreNanoSeconds might be nil during initial start of container so only fill if present
	if cpuUsage.UsageCoreNanoSeconds != nil {
		nanoCoreUsage := getUsageNanoCores(oldStats, cpuUsage.UsageCoreNanoSeconds.Value, timestamp)
		cpuUsage.UsageNanoCores = &runtime.UInt64Value{Value: nanoCoreUsage}
	}

	return cpuUsage, nil
}

func getUsageNanoCores(oldStats *stats.ContainerStats, cpuUsage uint64, timestamp time.Time) uint64 {
	if oldStats == nil {
		return 0
	}

	nanoSeconds := timestamp.UnixNano() - oldStats.Timestamp.UnixNano()

	// zero or negative interval
	if nanoSeconds <= 0 {
		return 0
	}

	return uint64(float64(cpuUsage-oldStats.UsageCoreNanoSeconds) /
		float64(nanoSeconds) * float64(time.Second/time.Nanosecond))
}

func (c *criService) memoryContainerStats(stats interface{}, timestamp time.Time) (*runtime.MemoryUsage, error) {
	switch metrics := stats.(type) {
	case *v1.Metrics:
		if metrics.Memory != nil && metrics.Memory.Usage != nil {
			workingSetBytes := getWorkingSet(metrics.Memory)

			return &runtime.MemoryUsage{
				Timestamp: timestamp.UnixNano(),
				WorkingSetBytes: &runtime.UInt64Value{
					Value: workingSetBytes,
				},
				AvailableBytes:  &runtime.UInt64Value{Value: getAvailableBytes(metrics.Memory, workingSetBytes)},
				UsageBytes:      &runtime.UInt64Value{Value: metrics.Memory.Usage.Usage},
				RssBytes:        &runtime.UInt64Value{Value: metrics.Memory.TotalRSS},
				PageFaults:      &runtime.UInt64Value{Value: metrics.Memory.TotalPgFault},
				MajorPageFaults: &runtime.UInt64Value{Value: metrics.Memory.TotalPgMajFault},
			}, nil
		}
	case *v2.Metrics:
		if metrics.Memory != nil {
			workingSetBytes := getWorkingSetV2(metrics.Memory)

			return &runtime.MemoryUsage{
				Timestamp: timestamp.UnixNano(),
				WorkingSetBytes: &runtime.UInt64Value{
					Value: workingSetBytes,
				},
				AvailableBytes: &runtime.UInt64Value{Value: getAvailableBytesV2(metrics.Memory, workingSetBytes)},
				UsageBytes:     &runtime.UInt64Value{Value: metrics.Memory.Usage},
				// Use Anon memory for RSS as cAdvisor on cgroupv2
				// see https://github.com/google/cadvisor/blob/a9858972e75642c2b1914c8d5428e33e6392c08a/container/libcontainer/handler.go#L799
				RssBytes:        &runtime.UInt64Value{Value: metrics.Memory.Anon},
				PageFaults:      &runtime.UInt64Value{Value: metrics.Memory.Pgfault},
				MajorPageFaults: &runtime.UInt64Value{Value: metrics.Memory.Pgmajfault},
			}, nil
		}
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
