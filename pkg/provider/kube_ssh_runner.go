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
	"github.com/deckhouse/lib-connection/pkg/ssh/gossh"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
)

type RunnerInterfaceWithSSH struct {
	sett settings.Settings

	sshProvider connection.SSHProvider

	currentSSHClient connection.SSHClient
	fromSwitchCall   connection.SSHClient

	currentSSHClientSession *session.SessionWithPrivateKeys

	loopsParams KubeProviderLoopsParams
}

func NewRunnerInterfaceWithSSH(sett settings.Settings, sshProvider connection.SSHProvider) *RunnerInterfaceWithSSH {
	return &RunnerInterfaceWithSSH{
		sshProvider: sshProvider,
		sett:        sett,
	}
}

func (r *RunnerInterfaceWithSSH) WithLoopParams(p KubeProviderLoopsParams) *RunnerInterfaceWithSSH {
	r.loopsParams = p
	return r
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

	return !session.CompareWithKeys(fromClient, r.currentSSHClientSession), nil
}

func (r *RunnerInterfaceWithSSH) SetNodeInterface(ctx context.Context, client *kube.KubernetesClient, opts ...SetNodeInterfaceOpt) error {
	options := &SetNodeInterfaceOpts{}
	for _, opt := range opts {
		opt(options)
	}

	cleanupIfChecksFailed := noCleanupOnFailChecks

	// can use fromSwitchCall because DefaultKubeProvider use mutex for all interfaces
	sshClient := r.fromSwitchCall
	if govalue.Nil(sshClient) {
		// this case if call NewAdditionalClient
		var err error
		sshClient, cleanupIfChecksFailed, err = r.getCurrentForAdditional(ctx, options)
		if err != nil {
			return err
		}
	}

	if options.RunChecks {
		if err := sshClient.Check().WithDelaySeconds(1).AwaitAvailability(ctx, r.loopsParams.AwaitAvailabilityOverSSH); err != nil {
			cleanupIfChecksFailed()
			return fmt.Errorf("await master available: %v", err)
		}
	}

	client.WithNodeInterface(ssh.NewNodeInterfaceWrapper(sshClient, r.sett))
	return nil
}

func (r *RunnerInterfaceWithSSH) Finalize() {
	if !govalue.Nil(r.fromSwitchCall) {
		r.currentSSHClient = r.fromSwitchCall
		r.updateSessionFromCurrent()
	}

	r.fromSwitchCall = nil
}

func (r *RunnerInterfaceWithSSH) updateSessionFromCurrent() {
	r.currentSSHClientSession = &session.SessionWithPrivateKeys{
		Session: r.currentSSHClient.Session().Copy(),
		Keys:    r.currentSSHClient.PrivateKeys(),
	}
}

func noCleanupOnFailChecks() {}

func (r *RunnerInterfaceWithSSH) getCurrentForAdditional(ctx context.Context, opts *SetNodeInterfaceOpts) (connection.SSHClient, func(), error) {
	if opts.NewNodeInterface {
		client, err := r.sshProvider.NewAdditionalClient(ctx)
		if err != nil {
			return nil, noCleanupOnFailChecks, err
		}

		cleanup := func() {
			// need stop only gossh client because cli ssh init agent for all
			if _, ok := client.(*gossh.Client); ok {
				client.Stop()
			}
		}

		return client, cleanup, nil
	}

	// need use if call NewAdditionalClient* before Client
	if !govalue.Nil(r.currentSSHClient) {
		return r.currentSSHClient, noCleanupOnFailChecks, nil
	}

	client, err := r.sshProvider.Client(ctx)
	if err != nil {
		return nil, noCleanupOnFailChecks, err
	}

	r.currentSSHClient = client
	r.updateSessionFromCurrent()

	return client, noCleanupOnFailChecks, nil
}
