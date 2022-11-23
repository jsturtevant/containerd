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
	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/log"
	sandboxstore "github.com/containerd/containerd/pkg/cri/store/sandbox"
	"github.com/containerd/containerd/pkg/cri/store/stats"
	"github.com/containerd/typeurl"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
	"time"
)

func (c *criService) metricsForSandbox(ctx context.Context, sandbox sandboxstore.Sandbox) (interface{}, error) {
	meta := sandbox.Metadata

	if sandbox.Status.Get().State != sandboxstore.StateReady {
		return nil, fmt.Errorf("failed to get pod sandbox stats since sandbox container %q is not in ready state", meta.ID)
	}

	request := &tasks.MetricsRequest{Filters: []string{"id==" + sandbox.ID}}
	resp, err := c.client.TaskService().Metrics(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metrics for pod sandbox: %w", err)
	}
	if len(resp.Metrics) != 1 {
		return nil, fmt.Errorf("Did not find exactly one pod sandbox: %+v", resp.Metrics)
	}

	s, err := typeurl.UnmarshalAny(resp.Metrics[0].Data)
	if err != nil {
		return nil, fmt.Errorf("failed to extract container metrics: %w", err)
	}

	return s, nil
}

func initializeStats(podSandboxStats *runtime.PodSandboxStats) {
	podSandboxStats.Windows = &runtime.WindowsPodSandboxStats{}
}

func setCPUStats(podSandboxStats *runtime.PodSandboxStats, cpuStats *runtime.CpuUsage) {
	wCpu := &runtime.WindowsCpuUsage{
		Timestamp:            cpuStats.Timestamp,
		UsageCoreNanoSeconds: cpuStats.UsageCoreNanoSeconds,
	}
	podSandboxStats.Windows.Cpu = wCpu
}

func setMemoryStats(podSandboxStats *runtime.PodSandboxStats, memoryStats *runtime.MemoryUsage) {
	wMemory := &runtime.WindowsMemoryUsage{
		Timestamp:       memoryStats.Timestamp,
		WorkingSetBytes: memoryStats.WorkingSetBytes,
		AvailableBytes:  memoryStats.AvailableBytes,
		PageFaults:      memoryStats.PageFaults,
	}

	podSandboxStats.Windows.Memory = wMemory
}

func setNetworkUsageStates(ctx context.Context, podSandboxStats *runtime.PodSandboxStats, sandbox sandboxstore.Sandbox) {
	eps, err := hcn.GetNamespaceEndpointIds(sandbox.NetNSPath)
	if err != nil {
		log.G(ctx).WithError(err).Errorf("unable to retrieve windows endpoint metrics for netNsPath: %v", sandbox.NetNSPath)
		return
	}
	podSandboxStats.Windows.Network = &runtime.WindowsNetworkUsage{
		Timestamp: time.Now().UnixNano(),
	}
	for _, ep := range eps {
		endpointStats, err := hcsshim.GetHNSEndpointStats(ep)
		if err != nil {
			fmt.Errorf("unable to gather stats for endpoints %w", err)
			continue
		}
		rtStats := runtime.WindowsNetworkInterfaceUsage{
			Name:             endpointStats.EndpointID,
			RxBytes:          &runtime.UInt64Value{Value: endpointStats.BytesReceived},
			RxPacketsDropped: &runtime.UInt64Value{Value: endpointStats.DroppedPacketsIncoming},
			TxBytes:          &runtime.UInt64Value{Value: endpointStats.BytesSent},
			TxPacketsDropped: &runtime.UInt64Value{Value: endpointStats.DroppedPacketsOutgoing},
		}
		podSandboxStats.Windows.Network.Interfaces = append(podSandboxStats.Windows.Network.Interfaces, &rtStats)

		// if the default interface isn't set add it.
		// We don't have a way to determine the default interface in windows
		if podSandboxStats.Windows.Network.DefaultInterface == nil {
			podSandboxStats.Windows.Network.DefaultInterface = &rtStats
		}
	}
}

func setPIDStats(podSandboxStats *runtime.PodSandboxStats, timestamp time.Time, pidCount uint64) {
	podSandboxStats.Windows.Process = &runtime.WindowsProcessUsage{
		Timestamp:    time.Now().UnixNano(),
		ProcessCount: &runtime.UInt64Value{Value: pidCount},
	}
}

func setContainerStats(podSandboxStats *runtime.PodSandboxStats, containerStats []*runtime.ContainerStats) {
	// Convert the stats to the "windows pod stats"
	// These are essentially the same for now
	// see https://github.com/kubernetes/enhancements/pull/3439
	windowsContainerStats := []*runtime.WindowsContainerStats{}
	for _, stat := range containerStats {
		wCpu := &runtime.WindowsCpuUsage{
			Timestamp:            stat.Cpu.Timestamp,
			UsageCoreNanoSeconds: stat.Cpu.UsageCoreNanoSeconds,
		}

		wMemory := &runtime.WindowsMemoryUsage{
			Timestamp:       stat.Memory.Timestamp,
			WorkingSetBytes: stat.Memory.WorkingSetBytes,
			AvailableBytes:  stat.Memory.AvailableBytes,
			PageFaults:      stat.Memory.PageFaults,
		}

		wFS := &runtime.WindowsFilesystemUsage{
			Timestamp: stat.WritableLayer.Timestamp,
			FsId:      stat.WritableLayer.FsId,
			UsedBytes: stat.WritableLayer.UsedBytes,
		}

		s := &runtime.WindowsContainerStats{
			Attributes:    stat.Attributes,
			Cpu:           wCpu,
			Memory:        wMemory,
			WritableLayer: wFS,
		}

		windowsContainerStats = append(windowsContainerStats, s)
	}
	podSandboxStats.Windows.Containers = windowsContainerStats
}

func (c *criService) saveSandBoxMetrics(cntrID string, sandboxStats *runtime.PodSandboxStats) error {
	// we may not have stats since container hasn't started yet so skip saving to cache
	if sandboxStats == nil || sandboxStats.Windows.Cpu == nil ||
		sandboxStats.Windows.Cpu.UsageCoreNanoSeconds == nil {
		return nil
	}

	newStats := &stats.ContainerStats{
		UsageCoreNanoSeconds: sandboxStats.Windows.Cpu.UsageCoreNanoSeconds.Value,
		Timestamp:            time.Unix(0, sandboxStats.Linux.Cpu.Timestamp),
	}
	return c.sandboxStore.UpdateContainerStats(cntrID, newStats)
}
