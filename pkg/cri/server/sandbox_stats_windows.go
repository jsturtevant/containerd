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

	"github.com/Microsoft/hcsshim"
	wstats "github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/stats"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/api/types"
	"github.com/containerd/containerd/log"
	containerstore "github.com/containerd/containerd/pkg/cri/store/container"
	sandboxstore "github.com/containerd/containerd/pkg/cri/store/sandbox"
	"github.com/containerd/containerd/pkg/cri/store/stats"
	"github.com/containerd/typeurl"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func (c *criService) podSandboxStats(
	ctx context.Context,
	sandbox sandboxstore.Sandbox) (*runtime.PodSandboxStats, error) {
	meta := sandbox.Metadata

	if sandbox.Status.Get().State != sandboxstore.StateReady {
		return nil, fmt.Errorf("failed to get pod sandbox stats since sandbox container %q is not in ready state", meta.ID)
	}

	podSandboxStats := &runtime.PodSandboxStats{}
	podSandboxStats.Windows = &runtime.WindowsPodSandboxStats{}
	podSandboxStats.Attributes = &runtime.PodSandboxAttributes{
		Id:          meta.ID,
		Metadata:    meta.Config.GetMetadata(),
		Labels:      meta.Config.GetLabels(),
		Annotations: meta.Config.GetAnnotations(),
	}

	metrics, containers, err := c.listWindowsMetricsForSandbox(ctx, sandbox)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain container stats during podSandboxStats call: %w", err)
	}
	podCPU, containerStats, err := c.toWindowsStats(metrics, sandbox, containers)
	if err != nil {
		return nil, fmt.Errorf("failed to convert container stats during podSandboxStats call: %w", err)
	}
	podSandboxStats.Windows.Cpu = podCPU.Cpu
	podSandboxStats.Windows.Memory = podCPU.Memory
	podSandboxStats.Windows.Containers = containerStats

	podSandboxStats.Windows.Network = windowsNetworkUsage(ctx, sandbox)

	pidCount, err := c.getSandboxPidCount(ctx, sandbox)
	if err != nil {
		return nil, err
	}
	timestamp := time.Now()
	podSandboxStats.Windows.Process = &runtime.WindowsProcessUsage{
		Timestamp:    timestamp.UnixNano(),
		ProcessCount: &runtime.UInt64Value{Value: pidCount},
	}

	return podSandboxStats, nil
}

func (c *criService) toWindowsStats(metrics []*types.Metric, sandbox sandboxstore.Sandbox, containers []containerstore.Container) (*runtime.WindowsContainerStats, []*runtime.WindowsContainerStats, error) {
	statsMap := make(map[string]*types.Metric)
	for _, stat := range metrics {
		statsMap[stat.ID] = stat
	}

	metric := statsMap[sandbox.ID]
	s, err := typeurl.UnmarshalAny(metric.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract container metrics: %w", err)
	}

	podStats := s.(*wstats.Statistics)
	podRuntimeStats, err := c.windowsCPUAndMemoryStats(podStats, sandbox.Stats)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract container metrics: %w", err)
	}

	windowsContainerStats := []*runtime.WindowsContainerStats{}
	for _, cntr := range containers {
		metric := statsMap[cntr.ID]
		s, err := typeurl.UnmarshalAny(metric.Data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to extract container metrics: %w", err)
		}

		containerStats := s.(*wstats.Statistics)
		containerRunTimeStats, err := c.windowsCPUAndMemoryStats(containerStats, cntr.Stats)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to extract container metrics: %w", err)
		}

		// On Windows we need to add up all the stats to get the Total for the Pod as there isn't something
		// like a parent cgroup that quiried for all the pod stats
		appendCPUPodStats(podRuntimeStats, containerRunTimeStats)
		appendMemoryPodStats(podRuntimeStats, containerRunTimeStats)

		// If snapshotstore doesn't have cached snapshot information
		// set WritableLayer usage to zero
		var usedBytes uint64
		sn, err := c.snapshotStore.Get(metric.ID)
		if err == nil {
			usedBytes = sn.Size
		}
		containerRunTimeStats.WritableLayer = &runtime.WindowsFilesystemUsage{
			Timestamp: sn.Timestamp,
			FsId: &runtime.FilesystemIdentifier{
				Mountpoint: c.imageFSPath,
			},
			UsedBytes: &runtime.UInt64Value{Value: usedBytes},
		}

		containerRunTimeStats.Attributes = &runtime.ContainerAttributes{
			Id:          cntr.ID,
			Metadata:    cntr.Config.GetMetadata(),
			Labels:      cntr.Config.GetLabels(),
			Annotations: cntr.Config.GetAnnotations(),
		}

		windowsContainerStats = append(windowsContainerStats, containerRunTimeStats)
	}

	return podRuntimeStats, windowsContainerStats, nil
}

func appendCPUPodStats(podRuntimeStats *runtime.WindowsContainerStats, containerRunTimeStats *runtime.WindowsContainerStats) {
	// protect against missing stats that we may not have stats since container hasn't started yet
	if podRuntimeStats.Cpu == nil || containerRunTimeStats.Cpu == nil {
		return
	}

	if podRuntimeStats.Cpu.UsageCoreNanoSeconds != nil && containerRunTimeStats.Cpu.UsageCoreNanoSeconds != nil {
		podRuntimeStats.Cpu.UsageCoreNanoSeconds.Value += containerRunTimeStats.Cpu.UsageCoreNanoSeconds.Value
	}
	if podRuntimeStats.Cpu.UsageNanoCores != nil && containerRunTimeStats.Cpu.UsageNanoCores != nil {
		podRuntimeStats.Cpu.UsageNanoCores.Value += containerRunTimeStats.Cpu.UsageNanoCores.Value
	}
}

func appendMemoryPodStats(podRuntimeStats *runtime.WindowsContainerStats, containerRunTimeStats *runtime.WindowsContainerStats) {
	// protect against missing stats that we may not have stats since container hasn't started yet
	if podRuntimeStats.Memory == nil || containerRunTimeStats.Memory == nil {
		return
	}

	if podRuntimeStats.Memory.WorkingSetBytes != nil && containerRunTimeStats.Memory.WorkingSetBytes != nil {
		podRuntimeStats.Memory.WorkingSetBytes.Value += containerRunTimeStats.Memory.WorkingSetBytes.Value
	}

	if podRuntimeStats.Memory.AvailableBytes != nil && containerRunTimeStats.Memory.AvailableBytes != nil {
		podRuntimeStats.Memory.AvailableBytes.Value += containerRunTimeStats.Memory.AvailableBytes.Value
	}

	if podRuntimeStats.Memory.PageFaults != nil && containerRunTimeStats.Memory.PageFaults != nil {
		podRuntimeStats.Memory.PageFaults.Value += containerRunTimeStats.Memory.PageFaults.Value
	}
}

func (c *criService) listWindowsMetricsForSandbox(ctx context.Context, sandbox sandboxstore.Sandbox) ([]*types.Metric, []containerstore.Container, error) {
	req := &tasks.MetricsRequest{}
	var containers []containerstore.Container
	for _, cntr := range c.containerStore.List() {
		if cntr.SandboxID != sandbox.ID {
			continue
		}
		containers = append(containers, cntr)
		req.Filters = append(req.Filters, "id=="+cntr.ID)
	}

	//add sandbox container as well
	req.Filters = append(req.Filters, "id=="+sandbox.ID)

	resp, err := c.client.TaskService().Metrics(ctx, req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch metrics for tasks: %w", err)
	}
	return resp.Metrics, containers, nil
}

func (c *criService) windowsCPUAndMemoryStats(stats *wstats.Statistics, oldStats *stats.ContainerStats) (*runtime.WindowsContainerStats, error) {
	var cs runtime.WindowsContainerStats
	if stats != nil {
		wstats := stats.GetWindows()
		if wstats == nil {
			return nil, fmt.Errorf("windows stats is empty")
		}
		if wstats.Processor != nil {
			cs.Cpu = &runtime.WindowsCpuUsage{
				Timestamp:            wstats.Timestamp.UnixNano(),
				UsageCoreNanoSeconds: &runtime.UInt64Value{Value: wstats.Processor.TotalRuntimeNS},
			}
		}

		// Calculate NanoCores
		if cs.Cpu.UsageCoreNanoSeconds != nil {
			nanoCoreUsage := getUsageNanoCores(oldStats, cs.Cpu.UsageCoreNanoSeconds.Value, wstats.Timestamp)
			cs.Cpu.UsageNanoCores = &runtime.UInt64Value{Value: nanoCoreUsage}
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

func windowsNetworkUsage(ctx context.Context, sandbox sandboxstore.Sandbox) *runtime.WindowsNetworkUsage {
	eps, err := hcn.GetNamespaceEndpointIds(sandbox.NetNSPath)
	if err != nil {
		log.G(ctx).WithError(err).Errorf("unable to retrieve windows endpoint metrics for netNsPath: %v", sandbox.NetNSPath)
		return nil
	}
	networkUsage := &runtime.WindowsNetworkUsage{
		Timestamp: time.Now().UnixNano(),
	}
	for _, ep := range eps {
		endpointStats, err := hcsshim.GetHNSEndpointStats(ep)
		if err != nil {
			log.G(ctx).WithError(err).Errorf("unable to gather stats for endpoint: %s", ep)
			continue
		}
		rtStats := runtime.WindowsNetworkInterfaceUsage{
			Name:             endpointStats.EndpointID,
			RxBytes:          &runtime.UInt64Value{Value: endpointStats.BytesReceived},
			RxPacketsDropped: &runtime.UInt64Value{Value: endpointStats.DroppedPacketsIncoming},
			TxBytes:          &runtime.UInt64Value{Value: endpointStats.BytesSent},
			TxPacketsDropped: &runtime.UInt64Value{Value: endpointStats.DroppedPacketsOutgoing},
		}
		networkUsage.Interfaces = append(networkUsage.Interfaces, &rtStats)

		// if the default interface isn't set add it.
		// We don't have a way to determine the default interface in windows
		if networkUsage.DefaultInterface == nil {
			networkUsage.DefaultInterface = &rtStats
		}
	}

	return networkUsage
}

func (c *criService) saveSandBoxMetrics(sandboxID string, sandboxStats *runtime.PodSandboxStats) error {
	// we may not have stats since container hasn't started yet so skip saving to cache
	if sandboxStats == nil || sandboxStats.Windows.Cpu == nil ||
		sandboxStats.Windows.Cpu.UsageCoreNanoSeconds == nil {
		return nil
	}

	newStats := &stats.ContainerStats{
		UsageCoreNanoSeconds: sandboxStats.Windows.Cpu.UsageCoreNanoSeconds.Value,
		Timestamp:            time.Unix(0, sandboxStats.Windows.Cpu.Timestamp),
	}
	err := c.sandboxStore.UpdateContainerStats(sandboxID, newStats)
	if err != nil {
		return err
	}

	// We queried the stats when getting sandbox stats.  We need to save the query to cache
	for _, cntr := range sandboxStats.Windows.Containers {
		// we may not have stats since container hasn't started yet so skip saving to cache
		if cntr == nil || cntr.Cpu == nil || cntr.Cpu.UsageCoreNanoSeconds == nil {
			return nil
		}

		newStats := &stats.ContainerStats{
			UsageCoreNanoSeconds: cntr.Cpu.UsageCoreNanoSeconds.Value,
			Timestamp:            time.Unix(0, cntr.Cpu.Timestamp),
		}
		err = c.containerStore.UpdateContainerStats(cntr.Attributes.Id, newStats)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *criService) getSandboxPidCount(ctx context.Context, sandbox sandboxstore.Sandbox) (uint64, error) {
	var pidCount uint64

	// get process count inside PodSandbox for Windows
	task, err := sandbox.Container.Task(ctx, nil)
	if err != nil {
		return 0, err
	}
	processes, err := task.Pids(ctx)
	if err != nil {
		return 0, err
	}
	pidCount += uint64(len(processes))

	for _, cntr := range c.containerStore.List() {
		if cntr.SandboxID != sandbox.ID {
			continue
		}

		state := cntr.Status.Get().State()
		if state != runtime.ContainerState_CONTAINER_RUNNING {
			continue
		}

		task, err := cntr.Container.Task(ctx, nil)
		if err != nil {
			return 0, err
		}

		processes, err := task.Pids(ctx)
		if err != nil {
			return 0, err
		}
		pidCount += uint64(len(processes))

	}

	return pidCount, nil
}
