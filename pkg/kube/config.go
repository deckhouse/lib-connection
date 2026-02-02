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
	"fmt"
	"strings"

	"github.com/name212/govalue"
	"k8s.io/client-go/rest"
)

type Config struct {
	KubeConfig        string
	KubeConfigContext string

	KubeConfigInCluster bool
	LocalKubeClient     bool

	RestConfig *rest.Config
}

func (c *Config) IsConflict() error {
	modes := map[string]bool{
		"kubeconfig": c.KubeConfig != "",
		"in-cluster": c.KubeConfigInCluster,
		"local":      c.LocalKubeClient,
		"rest":       c.IsRest(),
	}

	modesSet := make([]string, 0)

	for mode, isSet := range modes {
		if isSet {
			modesSet = append(modesSet, mode)
		}
	}

	if len(modesSet) > 1 {
		return fmt.Errorf("conflicting kube flags: set modes: %s", strings.Join(modesSet, " "))
	}

	return nil
}

func (c *Config) IsRest() bool {
	return !govalue.Nil(c.RestConfig)
}
