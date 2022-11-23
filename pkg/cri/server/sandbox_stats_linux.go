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
	"github.com/containerd/cgroups/v3"
	"github.com/containerd/cgroups/v3/cgroup1"
	cgroupsv2 "github.com/containerd/cgroups/v3/cgroup2"
	"github.com/containerd/containerd/log"
	sandboxstore "github.com/containerd/containerd/pkg/cri/store/sandbox"
	"github.com/containerd/containerd/pkg/cri/store/stats"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
	"time"
)

// https://github.com/cri-o/cri-o/blob/74a5cf8dffd305b311eb1c7f43a4781738c388c1/internal/oci/stats.go#L32
func getContainerNetIO(ctx context.Context, netNsPath string) (rxBytes, rxErrors, txBytes, txErrors uint64) {
	ns.WithNetNSPath(netNsPath, func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(defaultIfName)
		if err != nil {
			log.G(ctx).WithError(err).Errorf("unable to retrieve network namespace stats for netNsPath: %v, interface: %v", netNsPath, defaultIfName)
			return err
		}
		attrs := link.Attrs()
		if attrs != nil && attrs.Statistics != nil {
			rxBytes = attrs.Statistics.RxBytes
			rxErrors = attrs.Statistics.RxErrors
			txBytes = attrs.Statistics.TxBytes
			txErrors = attrs.Statistics.TxErrors
		}
		return nil
	})

	return rxBytes, rxErrors, txBytes, txErrors
}

func (c *criService) metricsForSandbox(ctx context.Context, sandbox sandboxstore.Sandbox) (interface{}, error) {
	cgroupPath := sandbox.Config.GetLinux().GetCgroupParent()

	if cgroupPath == "" {
		return nil, fmt.Errorf("failed to get cgroup metrics for sandbox %v because cgroupPath is empty", sandbox.ID)
	}

	var statsx interface{}
	if cgroups.Mode() == cgroups.Unified {
		cg, err := cgroupsv2.Load(cgroupPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load sandbox cgroup: %v: %w", cgroupPath, err)
		}
		stats, err := cg.Stat()
		if err != nil {
			return nil, fmt.Errorf("failed to get stats for cgroup: %v: %w", cgroupPath, err)
		}
		statsx = stats

	} else {
		control, err := cgroup1.Load(cgroup1.StaticPath(cgroupPath))
		if err != nil {
			return nil, fmt.Errorf("failed to load sandbox cgroup %v: %w", cgroupPath, err)
		}
		stats, err := control.Stat(cgroup1.IgnoreNotExist)
		if err != nil {
			return nil, fmt.Errorf("failed to get stats for cgroup %v: %w", cgroupPath, err)
		}
		statsx = stats
	}

	return statsx, nil
}

func initializeStats(podSandboxStats *runtime.PodSandboxStats) {
	podSandboxStats.Linux = &runtime.LinuxPodSandboxStats{}
}

func setCPUStats(podSandboxStats *runtime.PodSandboxStats, cpuStats *runtime.CpuUsage) {
	podSandboxStats.Linux.Cpu = cpuStats
}

func setMemoryStats(podSandboxStats *runtime.PodSandboxStats, memoryStats *runtime.MemoryUsage) {
	podSandboxStats.Linux.Memory = memoryStats
}

func setNetworkUsageStates(ctx context.Context, podSandboxStats *runtime.PodSandboxStats, sandbox sandboxstore.Sandbox) {
	if sandbox.NetNSPath != "" {
		rxBytes, rxErrors, txBytes, txErrors := getContainerNetIO(ctx, sandbox.NetNSPath)
		podSandboxStats.Linux.Network = &runtime.NetworkUsage{
			DefaultInterface: &runtime.NetworkInterfaceUsage{
				Name:     defaultIfName,
				RxBytes:  &runtime.UInt64Value{Value: rxBytes},
				RxErrors: &runtime.UInt64Value{Value: rxErrors},
				TxBytes:  &runtime.UInt64Value{Value: txBytes},
				TxErrors: &runtime.UInt64Value{Value: txErrors},
			},
		}
	}
}

func setPIDStats(podSandboxStats *runtime.PodSandboxStats, timestamp time.Time, pidCount uint64) {
	podSandboxStats.Linux.Process = &runtime.ProcessUsage{
		Timestamp:    timestamp.UnixNano(),
		ProcessCount: &runtime.UInt64Value{Value: pidCount},
	}
}

func setContainerStats(podSandboxStats *runtime.PodSandboxStats, containerStats []*runtime.ContainerStats) {
	podSandboxStats.Linux.Containers = containerStats
}

func (c *criService) saveSandBoxMetrics(cntrID string, sandboxStats *runtime.PodSandboxStats) error {
	// we may not have stats since container hasn't started yet so skip saving to cache
	if sandboxStats == nil || sandboxStats.Linux.Cpu == nil ||
		sandboxStats.Linux.Cpu.UsageCoreNanoSeconds == nil {
		return nil
	}

	newStats := &stats.ContainerStats{
		UsageCoreNanoSeconds: sandboxStats.Linux.Cpu.UsageCoreNanoSeconds.Value,
		Timestamp:            time.Unix(0, sandboxStats.Linux.Cpu.Timestamp),
	}
	return c.sandboxStore.UpdateContainerStats(cntrID, newStats)
}
