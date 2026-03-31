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

	"github.com/name212/govalue"

	"github.com/deckhouse/lib-connection/pkg/kube"
	"github.com/deckhouse/lib-connection/pkg/settings"
)

type SetNodeInterfaceOpts struct {
	RunChecks        bool
	NewNodeInterface bool
}

type SetNodeInterfaceOpt func(opts *SetNodeInterfaceOpts)

func SetNodeInterfaceOptWithRunChecks() SetNodeInterfaceOpt {
	return func(opts *SetNodeInterfaceOpts) {
		opts.RunChecks = true
	}
}

func SetNodeInterfaceOptWithNewNodeInterface() SetNodeInterfaceOpt {
	return func(opts *SetNodeInterfaceOpts) {
		opts.NewNodeInterface = true
	}
}

type RunnerInterface interface {
	IsSwitched(ctx context.Context) (bool, error)
	SetNodeInterface(ctx context.Context, client *kube.KubernetesClient, opts ...SetNodeInterfaceOpt) error
	Finalize(isError bool)
	InitOptions() []kube.InitOpt
}

type RunnerInterfaceOpt func(RunnerInterface)

func GetRunnerInterface(ctx context.Context, config *kube.Config, sett settings.Settings, sshInitializer SSHProviderInitializer, opts ...RunnerInterfaceOpt) (RunnerInterface, error) {
	r, err := getRunner(ctx, config, sett, sshInitializer)
	if err != nil {
		return nil, err
	}

	for _, o := range opts {
		o(r)
	}

	return r, nil
}

func RunnerInterfaceWithSSHLoopsParams(p RunnerInterfaceSSHLoopsParams) RunnerInterfaceOpt {
	return func(r RunnerInterface) {
		sshRI, ok := r.(*RunnerInterfaceSSH)
		if ok {
			sshRI.WithLoopParams(p)
		}
	}
}

func RunnerInterfaceWithInitOpts(opts ...kube.InitOpt) RunnerInterfaceOpt {
	return func(r RunnerInterface) {
		sshRI, ok := r.(*RunnerInterfaceSSH)
		if ok {
			sshRI.WithInitOptions(opts...)
		}
	}
}

func getRunner(ctx context.Context, config *kube.Config, sett settings.Settings, sshInitializer SSHProviderInitializer) (RunnerInterface, error) {
	if err := config.IsConflict(); err != nil {
		return nil, err
	}

	switch {
	case config.KubeConfigInCluster:
		fallthrough
	case config.KubeConfig != "":
		fallthrough
	case config.IsRest():
		return &RunnerInterfaceNoAction{}, nil
	case config.LocalKubeClient:
		return NewRunnerInterfaceLocal(sett), nil
	}

	if govalue.Nil(sshInitializer) {
		return nil, fmt.Errorf("SSH provider initializer should passed for create kubernetes client over ssh")
	}

	sshProvider, err := sshInitializer.GetSSHProvider(ctx)
	if err != nil {
		return nil, err
	}

	if govalue.Nil(sshProvider) {
		return nil, fmt.Errorf("SSH provider initializer return nil ssh provider")
	}

	return NewRunnerInterfaceSSH(sett, sshProvider), nil
}
