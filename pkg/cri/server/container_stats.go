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
	"time"

	tasks "github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/api/types"
	containerstore "github.com/containerd/containerd/pkg/cri/store/container"
	"github.com/containerd/containerd/pkg/cri/store/stats"
	"github.com/containerd/containerd/protobuf"
	"github.com/containerd/typeurl"
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

func (c *criService) cpuContainerStats(oldStats *stats.ContainerStats, newStats interface{}, timestamp time.Time) (*runtime.CpuUsage, error) {
	cpuUsage, err := createCPUStats(newStats, timestamp)
	if err != nil {
		return nil, err
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
