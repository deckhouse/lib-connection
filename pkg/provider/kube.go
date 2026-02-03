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
	"fmt"
	"sync"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/log"
	"github.com/deckhouse/lib-dhctl/pkg/retry"
	"github.com/name212/govalue"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/kube"
	"github.com/deckhouse/lib-connection/pkg/settings"
)

var (
	_ connection.KubeProvider = &DefaultKubeProvider{}
)

type KubeProviderLoopsParams struct {
	AwaitAvailabilityOverSSH retry.Params
	InitClient               retry.Params
	WaitingReady             retry.Params
}

type DefaultKubeProvider struct {
	mu sync.Mutex

	sett   settings.Settings
	config *kube.Config

	currentClient connection.KubeClient

	runnerInterface RunnerInterface

	loopsParams KubeProviderLoopsParams

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
		client, err := p.createAndInitClient(ctx, true)
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

	return p.createAndInitClient(ctx, true)
}

// NewAdditionalClientWithoutInitialize
// create new additional client without initialize
func (p *DefaultKubeProvider) NewAdditionalClientWithoutInitialize(ctx context.Context) (connection.KubeClient, error) {
	// need lock for safe call RunnerInterface.SetNodeInterface
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.createAndInitClient(ctx, false)
}

func (p *DefaultKubeProvider) Cleanup(context.Context) error {
	return nil
}

func (p *DefaultKubeProvider) newClient(ctx context.Context, enableAdditionalCheck bool) (*kube.KubernetesClient, error) {
	client := kube.NewKubernetesClient(p.sett)
	if err := p.runnerInterface.SetNodeInterface(ctx, client, enableAdditionalCheck); err != nil {
		return nil, err
	}

	return client, nil
}

func (p *DefaultKubeProvider) createAndInitClient(ctx context.Context, init bool) (connection.KubeClient, error) {
	config := p.config

	if err := config.IsConflict(); err != nil {
		return nil, err
	}

	if !init {
		return p.newClient(ctx, false)
	}

	var opts []kube.InitOpt

	if p.noStartKubeProxy {
		opts = append(opts, kube.InitWithNoStartKubeProxy())
	}

	logger := p.sett.Logger()

	var client *kube.KubernetesClient

	err := logger.Process(log.ProcessCommon, "Connect to Kubernetes API", func() error {
		// await availability if need here
		newClient, err := p.newClient(ctx, true)
		if err != nil {
			return err
		}

		if err := p.connectToKubernetesAPI(ctx, newClient, opts); err != nil {
			return err
		}

		client = newClient

		return nil
	})

	if err != nil {
		return nil, err
	}

	return client, nil
}

func (p *DefaultKubeProvider) connectToKubernetesAPI(ctx context.Context, client *kube.KubernetesClient, kubeInitOpts []kube.InitOpt) error {
	logger := p.sett.Logger()

	initClientLoopParams := retry.SafeCloneOrNewParams(p.loopsParams.InitClient, defaultInitClientParamsOpts...).Clone(
		retry.WithName("Get Kubernetes API client"),
		retry.WithLogger(logger),
	)

	err := retry.NewLoopWithParams(initClientLoopParams).RunContext(ctx, func() error {
		if err := client.InitContext(ctx, p.config, kubeInitOpts...); err != nil {
			return fmt.Errorf("open kubernetes connection: %v", err)
		}
		return nil
	})

	if err != nil {
		return err
	}

	time.Sleep(50 * time.Millisecond) // tick to prevent first probable fail

	readyLoopParams := retry.SafeCloneOrNewParams(p.loopsParams.WaitingReady, defaultWaitingReadyParamsOpts...).Clone(
		retry.WithName("Waiting for Kubernetes API to become Ready"),
		retry.WithLogger(logger),
	)

	return retry.NewLoopWithParams(readyLoopParams).RunContext(ctx, func() error {
		_, err := client.Discovery().ServerVersion()
		if err == nil {
			return nil
		}
		return fmt.Errorf("kubernetes API is not Ready: %w", err)
	})
}

var defaultInitClientParamsOpts = []retry.ParamsBuilderOpt{
	retry.WithWait(5 * time.Second),
	retry.WithAttempts(45),
}

var defaultWaitingReadyParamsOpts = []retry.ParamsBuilderOpt{
	retry.WithWait(5 * time.Second),
	retry.WithAttempts(45),
}
