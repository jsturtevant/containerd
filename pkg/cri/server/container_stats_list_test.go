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
	"testing"
	"time"

	containerstore "github.com/containerd/containerd/pkg/cri/store/container"
	"github.com/containerd/containerd/pkg/cri/store/stats"
	"github.com/stretchr/testify/assert"
)

func TestContainerMetricsCPUNanoCoreUsage(t *testing.T) {
	timestamp := time.Now()
	secondAfterTimeStamp := timestamp.Add(time.Second)
	ID := "ID"

	for desc, test := range map[string]struct {
		firstCPUValue               uint64
		secondCPUValue              uint64
		expectedNanoCoreUsageFirst  uint64
		expectedNanoCoreUsageSecond uint64
	}{
		"metrics": {
			firstCPUValue:               50,
			secondCPUValue:              500,
			expectedNanoCoreUsageFirst:  0,
			expectedNanoCoreUsageSecond: 450,
		},
	} {
		t.Run(desc, func(t *testing.T) {
			container, err := containerstore.NewContainer(
				containerstore.Metadata{ID: ID},
			)
			assert.NoError(t, err)

			// calculate for first iteration
			// first run so container stats will be nil
			assert.Nil(t, container.Stats)
			cpuUsage := getUsageNanoCores(container.Stats, test.firstCPUValue, timestamp)
			assert.NoError(t, err)
			assert.Equal(t, test.expectedNanoCoreUsageFirst, cpuUsage)

			// fill in the stats as if they now exist
			container.Stats = &stats.ContainerStats{}
			container.Stats.UsageCoreNanoSeconds = test.firstCPUValue
			container.Stats.Timestamp = timestamp
			assert.NotNil(t, container.Stats)

			// calculate for second iteration
			cpuUsage = getUsageNanoCores(container.Stats, test.secondCPUValue, secondAfterTimeStamp)
			assert.NoError(t, err)
			assert.Equal(t, test.expectedNanoCoreUsageSecond, cpuUsage)
		})
	}

}
