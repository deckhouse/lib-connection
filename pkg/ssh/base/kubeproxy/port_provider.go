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

package kubeproxy

import (
	"github.com/deckhouse/lib-connection/pkg/utils/rand"
)

const (
	DefaultLocalAPIPort = 22322

	kubeProxyPortRangeStart = 22340
	kubeProxyPortRangeEnd   = 22499
)

type PortProvider struct {
	used      map[int]struct{}
	startPort int
}

func NewPortProvider(startPort int) *PortProvider {
	return &PortProvider{
		used:      make(map[int]struct{}),
		startPort: startPort,
	}
}

func (p *PortProvider) Next() int {
	if p.startPort > 0 {
		return p.startPort
	}

	if len(p.used) == 0 {
		return p.addToUsedAndReturn(DefaultLocalAPIPort)
	}

	nextPort := rand.RangeExclude(kubeProxyPortRangeStart, kubeProxyPortRangeEnd, p.used)
	return p.addToUsedAndReturn(nextPort)
}

func (p *PortProvider) addToUsedAndReturn(port int) int {
	p.used[port] = struct{}{}
	return port
}
