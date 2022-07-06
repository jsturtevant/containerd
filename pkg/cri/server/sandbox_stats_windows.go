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
	wstats "github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/stats"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/api/types"
	sandboxstore "github.com/containerd/containerd/pkg/cri/store/sandbox"
	"github.com/containerd/typeurl"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
	"time"
)

func (c *criService) podSandboxStats(ctx context.Context, sandbox sandboxstore.Sandbox, stats interface{}) (*runtime.PodSandboxStats, error) {
	meta := sandbox.Metadata

	if sandbox.Status.Get().State != sandboxstore.StateReady {
		return nil, fmt.Errorf("failed to get pod sandbox stats since sandbox container %q is not in ready state", meta.ID)
	}

	var podSandboxStats runtime.PodSandboxStats
	podSandboxStats.Attributes = &runtime.PodSandboxAttributes{
		Id:          meta.ID,
		Metadata:    meta.Config.GetMetadata(),
		Labels:      meta.Config.GetLabels(),
		Annotations: meta.Config.GetAnnotations(),
	}

	podSandboxStats.Windows = &runtime.WindowsPodSandboxStats{}

	if stats != nil {
		metrics, ok := stats.(*types.Metric)
		if !ok {
			return nil, fmt.Errorf("failed to extract windows container metrics %s", stats)
		}

		// cpu and memory
		cs, err := windowsCpuAndMemoryStats(metrics)
		if err != nil {
			return nil, fmt.Errorf("failed to extract windows container metrics %s", stats)
		}
		podSandboxStats.Windows.Cpu = cs.Cpu
		podSandboxStats.Windows.Memory = cs.Memory
		if cs.Cpu != nil && cs.Cpu.UsageCoreNanoSeconds != nil {
			// this is a calculated value and should be computed for all OSes
			nanoUsage, err := c.getUsageNanoCores(meta.ID, true, cs.Cpu.UsageCoreNanoSeconds.Value, time.Unix(0, cs.Cpu.Timestamp))
			if err != nil {
				return nil, fmt.Errorf("failed to get usage nano cores, containerID: %s: %w", meta.ID, err)
			}
			podSandboxStats.Windows.Cpu.UsageNanoCores = &runtime.UInt64Value{Value: nanoUsage}
		}

		pidCount, err := c.getSandboxPidCount(ctx, sandbox)
		if err != nil {
			return nil, err
		}
		podSandboxStats.Windows.Process = &runtime.WindowsProcessUsage{
			Timestamp:    time.Now().UnixNano(),
			ProcessCount: &runtime.UInt64Value{Value: pidCount},
		}

		// network stats for pod
		eps, err := hcn.GetNamespaceEndpointIds(sandbox.NetNSPath)
		if err != nil {
			return nil, fmt.Errorf("failed to extract windows endpoint metrics %w", err)
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

		// container stats
		listContainerStatsRequest := &runtime.ListContainerStatsRequest{Filter: &runtime.ContainerStatsFilter{PodSandboxId: meta.ID}}
		resp, err := c.ListContainerStats(ctx, listContainerStatsRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to obtain container stats during podSandboxStats call: %w", err)
		}

		// Convert the stats to the "windows pod stats"
		// see https://github.com/kubernetes/enhancements/pull/3439
		containerStats := resp.GetStats()
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

	return &podSandboxStats, nil
}

func windowsCpuAndMemoryStats(stats *types.Metric) (*runtime.WindowsContainerStats, error) {
	var cs runtime.WindowsContainerStats
	if stats != nil {
		s, err := typeurl.UnmarshalAny(stats.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to extract container metrics: %w", err)
		}
		wstats := s.(*wstats.Statistics).GetWindows()
		if wstats == nil {
			return nil, fmt.Errorf("windows stats is empty")
		}
		if wstats.Processor != nil {
			cs.Cpu = &runtime.WindowsCpuUsage{
				Timestamp:            wstats.Timestamp.UnixNano(),
				UsageCoreNanoSeconds: &runtime.UInt64Value{Value: wstats.Processor.TotalRuntimeNS},
			}
		}
		if wstats.Memory != nil {
			cs.Memory = &runtime.WindowsMemoryUsage{
				Timestamp: wstats.Timestamp.UnixNano(),
				WorkingSetBytes: &runtime.UInt64Value{
					Value: wstats.Memory.MemoryUsagePrivateWorkingSetBytes,
				},
			}
		}
	}
	return &cs, nil
}

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

	return resp.Metrics[0], nil
}
