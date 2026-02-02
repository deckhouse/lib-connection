// Copyright 2026 Flant JSC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kube

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

func TestConfigIsConflict(t *testing.T) {
	type testCase struct {
		name   string
		config *Config
	}

	t.Run("no conflict", func(t *testing.T) {
		configs := []testCase{
			{
				name:   "empty",
				config: &Config{},
			},
			{
				name: "kube config",
				config: &Config{
					KubeConfig: "/tmp/not-exists.rgg4g4.yaml",
				},
			},
			{
				name: "in cluster",
				config: &Config{
					KubeConfigInCluster: true,
				},
			},
			{
				name: "local",
				config: &Config{
					LocalKubeClient: true,
				},
			},
			{
				name: "rest",
				config: &Config{
					RestConfig: &rest.Config{},
				},
			},
		}

		for _, c := range configs {
			t.Run(c.name, func(t *testing.T) {
				err := c.config.IsConflict()
				require.NoError(t, err, "should not conflict")
			})
		}
	})

	t.Run("conflict", func(t *testing.T) {
		configs := []testCase{
			{
				name: "local with kube config",
				config: &Config{
					LocalKubeClient: true,
					KubeConfig:      "/tmp/not-exists.rgg4g4.yaml",
				},
			},
			{
				name: "kube config with in cluster",
				config: &Config{
					KubeConfig:          "/tmp/not-exists.rgg4g4.yaml",
					KubeConfigInCluster: true,
				},
			},
			{
				name: "local with in cluster",
				config: &Config{
					LocalKubeClient:     true,
					KubeConfigInCluster: true,
				},
			},
			{
				name: "kube config and rest",
				config: &Config{
					KubeConfig: "/tmp/not-exists.rgg4g4.yaml",
					RestConfig: &rest.Config{},
				},
			},
			{
				name: "local with kube config and rest",
				config: &Config{
					LocalKubeClient: true,
					KubeConfig:      "/tmp/not-exists.rgg4g4.yaml",
					RestConfig:      &rest.Config{},
				},
			},
			{
				name: "all",
				config: &Config{
					KubeConfigInCluster: true,
					LocalKubeClient:     true,
					KubeConfig:          "/tmp/not-exists.rgg4g4.yaml",
					RestConfig:          &rest.Config{},
				},
			},
		}

		for _, c := range configs {
			t.Run(c.name, func(t *testing.T) {
				err := c.config.IsConflict()
				require.Error(t, err, "should conflict")
			})
		}
	})
}
