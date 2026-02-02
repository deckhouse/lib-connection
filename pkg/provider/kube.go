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
	"sync"

	"github.com/name212/govalue"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/kube"
	"github.com/deckhouse/lib-connection/pkg/settings"
)

var (
	_ connection.KubeProvider = &DefaultKubeProvider{}
)

type DefaultKubeProvider struct {
	mu sync.Mutex

	sett   settings.Settings
	config *kube.Config

	currentClient connection.KubeClient

	runnerInterface RunnerInterface

	// use for testing only
	noStartKubeProxy bool
}

// NewDefaultKubeProvider
// if use rest config sshProvider can be nil
func NewDefaultKubeProvider(sett settings.Settings, config *kube.Config, runnerInterface RunnerInterface) *DefaultKubeProvider {
	return &DefaultKubeProvider{
		sett:            sett,
		config:          config,
		runnerInterface: runnerInterface,
	}
}

func (p *DefaultKubeProvider) Client(ctx context.Context) (connection.KubeClient, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	switched, err := p.runnerInterface.IsSwitched(ctx)
	if err != nil {
		return nil, err
	}

	if govalue.Nil(p.currentClient) || switched {
		client, err := p.newClient(ctx, true)
		if err != nil {
			return nil, err
		}

		p.currentClient = client
		p.runnerInterface.Finalize()

		return client, nil
	}

	return p.currentClient, nil
}

func (p *DefaultKubeProvider) NewAdditionalClient(ctx context.Context) (connection.KubeClient, error) {
	// need lock for safe call RunnerInterface.SetNodeInterface
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.newClient(ctx, true)
}

// NewAdditionalClientWithoutInitialize
// create new additional client without initialize
func (p *DefaultKubeProvider) NewAdditionalClientWithoutInitialize(ctx context.Context) (connection.KubeClient, error) {
	// need lock for safe call RunnerInterface.SetNodeInterface
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.newClient(ctx, false)
}

func (p *DefaultKubeProvider) Cleanup(context.Context) error {
	return nil
}

func (p *DefaultKubeProvider) newClient(ctx context.Context, init bool) (connection.KubeClient, error) {
	config := p.config

	if err := config.IsConflict(); err != nil {
		return nil, err
	}

	client := kube.NewKubernetesClient(p.sett)

	if err := p.runnerInterface.SetNodeInterface(ctx, client); err != nil {
		return nil, err
	}

	if !init {
		return client, nil
	}

	var opts []kube.InitOpt

	if p.noStartKubeProxy {
		opts = append(opts, kube.InitWithNoStartKubeProxy())
	}

	if err := client.InitContext(ctx, config, opts...); err != nil {
		return nil, err
	}

	return client, nil
}
