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

package provider

import (
	"context"

	"github.com/deckhouse/lib-connection/pkg/kube"
	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/local"
)

type RunnerInterfaceLocal struct {
	node *local.NodeInterface
}

func NewRunnerInterfaceLocal(sett settings.Settings) *RunnerInterfaceLocal {
	return &RunnerInterfaceLocal{
		node: local.NewNodeInterface(sett),
	}
}

func (r *RunnerInterfaceLocal) IsSwitched(context.Context) (bool, error) {
	return false, nil
}

func (r *RunnerInterfaceLocal) Finalize(bool) {}

func (r *RunnerInterfaceLocal) SetNodeInterface(_ context.Context, client *kube.KubernetesClient, _ ...SetNodeInterfaceOpt) error {
	client.WithNodeInterface(r.node)
	return nil
}

func (r *RunnerInterfaceLocal) InitOptions() []kube.InitOpt {
	return nil
}
