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

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/kube"
	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh"
	"github.com/deckhouse/lib-connection/pkg/ssh/local"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
)

type RunnerInterface interface {
	IsSwitched(ctx context.Context) (bool, error)
	SetNodeInterface(ctx context.Context, client *kube.KubernetesClient) error
	Finalize()
}

func GetRunnerInterface(config *kube.Config, sett settings.Settings, sshProvider connection.SSHProvider) (RunnerInterface, error) {
	if err := config.IsConflict(); err != nil {
		return nil, err
	}

	switch {
	case config.KubeConfigInCluster:
	case config.KubeConfig != "":
	case config.IsRest():
		return &RunnerInterfaceNoAction{}, nil
	case config.LocalKubeClient:
		return NewRunnerInterfaceLocal(sett), nil
	}

	if govalue.Nil(sshProvider) {
		return nil, fmt.Errorf("No SSH provider specified for create kubernetes client over ssh")
	}

	return NewRunnerInterfaceWithSSH(sett, sshProvider), nil
}

type RunnerInterfaceNoAction struct{}

func (*RunnerInterfaceNoAction) IsSwitched(context.Context) (bool, error) {
	return false, nil
}

func (*RunnerInterfaceNoAction) Finalize() {}

func (*RunnerInterfaceNoAction) SetNodeInterface(context.Context, *kube.KubernetesClient) error {
	return nil
}

type RunnerInterfaceWithSSH struct {
	sett settings.Settings

	sshProvider connection.SSHProvider

	currentSSHClient connection.SSHClient
	fromSwitchCall   connection.SSHClient

	currentSSHClientSession *session.SessionWithPrivateKeys
}

func NewRunnerInterfaceWithSSH(sett settings.Settings, sshProvider connection.SSHProvider) *RunnerInterfaceWithSSH {
	return &RunnerInterfaceWithSSH{
		sshProvider: sshProvider,
		sett:        sett,
	}
}

func (r *RunnerInterfaceWithSSH) IsSwitched(ctx context.Context) (bool, error) {
	sshClient, err := r.sshProvider.Client(ctx)
	if err != nil {
		return false, err
	}

	fromClient := &session.SessionWithPrivateKeys{
		Session: sshClient.Session(),
		Keys:    sshClient.PrivateKeys(),
	}

	r.fromSwitchCall = sshClient

	return session.CompareWithKeys(fromClient, r.currentSSHClientSession), nil
}

func (r *RunnerInterfaceWithSSH) SetNodeInterface(ctx context.Context, client *kube.KubernetesClient) error {
	// can use fromSwitchCall because DefaultKubeProvider use mutex for all interfaces
	sshClient := r.fromSwitchCall
	if govalue.Nil(sshClient) {
		var err error
		sshClient, err = r.getCurrent(ctx)
		if err != nil {
			return err
		}
	}

	client.WithNodeInterface(ssh.NewNodeInterfaceWrapper(sshClient, r.sett))
	return nil
}

func (r *RunnerInterfaceWithSSH) Finalize() {
	if !govalue.Nil(r.fromSwitchCall) {
		r.currentSSHClient = r.fromSwitchCall
	}

	r.fromSwitchCall = nil
}

func (r *RunnerInterfaceWithSSH) updateSessionFromCurrent() {
	r.currentSSHClientSession = &session.SessionWithPrivateKeys{
		Session: r.currentSSHClient.Session().Copy(),
		Keys:    r.currentSSHClient.PrivateKeys(),
	}
}

func (r *RunnerInterfaceWithSSH) getCurrent(ctx context.Context) (connection.SSHClient, error) {
	// need use if call NewAdditionalClient* before Client
	if !govalue.Nil(r.currentSSHClient) {
		return r.currentSSHClient, nil
	}

	client, err := r.sshProvider.Client(ctx)
	if err != nil {
		return nil, err
	}

	r.currentSSHClient = client
	r.updateSessionFromCurrent()

	return client, nil
}

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

func (r *RunnerInterfaceLocal) Finalize() {}

func (r *RunnerInterfaceLocal) SetNodeInterface(_ context.Context, client *kube.KubernetesClient) error {
	client.WithNodeInterface(r.node)
	return nil
}
