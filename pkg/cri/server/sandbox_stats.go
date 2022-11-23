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
	sandboxstore "github.com/containerd/containerd/pkg/cri/store/sandbox"
	"time"

	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func (c *criService) PodSandboxStats(
	ctx context.Context,
	r *runtime.PodSandboxStatsRequest,
) (*runtime.PodSandboxStatsResponse, error) {

	sandbox, err := c.sandboxStore.Get(r.GetPodSandboxId())
	if err != nil {
		return nil, fmt.Errorf("an error occurred when trying to find sandbox %s: %w", r.GetPodSandboxId(), err)
	}

	metrics, err := c.metricsForSandbox(ctx, sandbox)
	if err != nil {
		return nil, fmt.Errorf("failed getting metrics for sandbox %s: %w", r.GetPodSandboxId(), err)
	}

	podSandboxStats, err := c.podSandboxStats(ctx, sandbox, metrics)
	if err != nil {
		return nil, fmt.Errorf("failed to decode pod sandbox metrics %s: %w", r.GetPodSandboxId(), err)
	}

	// save updated metrics in the cache
	// don't need to save each container stat since we use ListContainerStats which handles this
	err = c.saveSandBoxMetrics(sandbox.ID, podSandboxStats)
	if err != nil {
		return nil, fmt.Errorf("failed to update container stats ID: %s: %w", sandbox.Metadata.ID, err)
	}

	return &runtime.PodSandboxStatsResponse{Stats: podSandboxStats}, nil
}

func (c *criService) podSandboxStats(
	ctx context.Context,
	sandbox sandboxstore.Sandbox,
	stats interface{},
) (*runtime.PodSandboxStats, error) {
	meta := sandbox.Metadata

	if sandbox.Status.Get().State != sandboxstore.StateReady {
		return nil, fmt.Errorf("failed to get pod sandbox stats since sandbox container %q is not in ready state", meta.ID)
	}

	podSandboxStats := &runtime.PodSandboxStats{}
	podSandboxStats.Attributes = &runtime.PodSandboxAttributes{
		Id:          meta.ID,
		Metadata:    meta.Config.GetMetadata(),
		Labels:      meta.Config.GetLabels(),
		Annotations: meta.Config.GetAnnotations(),
	}

	initializeStats(podSandboxStats)

	if stats != nil {
		timestamp := time.Now()

		cpuStats, err := c.cpuContainerStats(sandbox.Stats, stats, timestamp)
		if err != nil {
			return nil, fmt.Errorf("failed to obtain cpu stats: %w", err)
		}
		setCPUStats(podSandboxStats, cpuStats)

		memoryStats, err := c.memoryContainerStats(stats, timestamp)
		if err != nil {
			return nil, fmt.Errorf("failed to obtain memory stats: %w", err)
		}
		setMemoryStats(podSandboxStats, memoryStats)

		setNetworkUsageStates(ctx, podSandboxStats, sandbox)

		pidCount, err := c.getSandboxPidCount(ctx, sandbox)
		if err != nil {
			return nil, err
		}
		setPIDStats(podSandboxStats, timestamp, pidCount)

		listContainerStatsRequest := &runtime.ListContainerStatsRequest{Filter: &runtime.ContainerStatsFilter{PodSandboxId: meta.ID}}
		resp, err := c.ListContainerStats(ctx, listContainerStatsRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to obtain container stats during podSandboxStats call: %w", err)
		}
		setContainerStats(podSandboxStats, resp.GetStats())
	}

	return podSandboxStats, nil
}
