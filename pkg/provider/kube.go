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
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
)

var (
	_ connection.KubeProvider = &DefaultKubeProvider{}
)

type DefaultKubeProvider struct {
	mu sync.Mutex

	sett   settings.Settings
	config *kube.Config

	currentClient connection.KubeClient

	sshProvider             connection.SSHProvider
	currentSSHClientSession *session.SessionWithPrivateKeys

	// use for testing only
	noStartKubeProxy bool
}

func NewDefaultKubeProvider(sett settings.Settings, config *kube.Config, sshProvider connection.SSHProvider) *DefaultKubeProvider {
	return &DefaultKubeProvider{
		sett:        sett,
		config:      config,
		sshProvider: sshProvider,
	}
}

func (p *DefaultKubeProvider) Client(ctx context.Context) (connection.KubeClient, error) {
	sshClient, err := p.getSSHClient(ctx)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if govalue.Nil(p.currentClient) || !p.hasSameSession(sshClient) {
		client, err := p.newClient(ctx, sshClient, true)
		if err != nil {
			return nil, err
		}

		p.setCurrent(client, sshClient)

		return client, nil
	}

	return p.currentClient, nil
}

func (p *DefaultKubeProvider) NewAdditionalClient(ctx context.Context) (connection.KubeClient, error) {
	sshClient, err := p.getSSHClient(ctx)
	if err != nil {
		return nil, err
	}

	return p.newClient(ctx, sshClient, true)
}

// NewAdditionalClientWithoutInitialize
// create new additional client without initialize
func (p *DefaultKubeProvider) NewAdditionalClientWithoutInitialize(ctx context.Context) (connection.KubeClient, error) {
	sshClient, err := p.getSSHClient(ctx)
	if err != nil {
		return nil, err
	}

	return p.newClient(ctx, sshClient, false)
}

func (p *DefaultKubeProvider) Cleanup(context.Context) error {
	return nil
}

func (p *DefaultKubeProvider) newClient(ctx context.Context, sshClient connection.SSHClient, init bool) (connection.KubeClient, error) {
	config := p.config

	if err := config.IsConflict(); err != nil {
		return nil, err
	}

	client := kube.NewKubernetesClient(p.sett)
	client.WithNodeInterface(sshClient)

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

func (p *DefaultKubeProvider) getSSHClient(ctx context.Context) (connection.SSHClient, error) {
	if p.config.IsRest() {
		return nil, nil
	}

	return p.sshProvider.Client(ctx)
}

func (p *DefaultKubeProvider) setCurrent(client connection.KubeClient, sshClient connection.SSHClient) {
	var sees *session.SessionWithPrivateKeys
	if !govalue.Nil(sshClient) {
		sees = &session.SessionWithPrivateKeys{
			Session: sshClient.Session(),
			Keys:    sshClient.PrivateKeys(),
		}
	}

	p.currentSSHClientSession = sees
	p.currentClient = client
}

func (p *DefaultKubeProvider) hasSameSession(sshClient connection.SSHClient) bool {
	var fromClient *session.SessionWithPrivateKeys
	if !govalue.Nil(sshClient) {
		fromClient = &session.SessionWithPrivateKeys{
			Session: sshClient.Session(),
			Keys:    sshClient.PrivateKeys(),
		}
	}

	return session.CompareWithKeys(fromClient, p.currentSSHClientSession)
}
