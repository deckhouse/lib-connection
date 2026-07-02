// Copyright 2025 Flant JSC
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

package gossh

import (
	"context"
	"fmt"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/ssh/base/kubeproxy"
)

var (
	_ connection.KubeProxy = &KubeProxy{}
)

type KubeProxy struct {
	*kubeproxy.BaseKubeProxy
}

func NewKubeProxy(client *Client) *KubeProxy {
	runner := newKubeProxyRunner(context.Background(), client)
	return &KubeProxy{
		BaseKubeProxy: kubeproxy.NewBaseKubeProxy(runner, client.settings, client.Session()),
	}
}

type kubeProxyRunner struct {
	client *Client
	ctx    context.Context
}

func newKubeProxyRunner(ctx context.Context, client *Client) *kubeProxyRunner {
	return &kubeProxyRunner{
		client: client,
		ctx:    ctx,
	}
}

func (r *kubeProxyRunner) StartCommand(params kubeproxy.StartCommandParams) (connection.KubeProxyCommand, error) {
	cmd := NewSSHCommand(r.client, params.Cmd)
	cmd.Sudo(r.ctx)

	cmd.OnCommandStart(params.OnStart)
	cmd.WithStdoutHandler(params.StdoutHandler)
	cmd.WithWaitHandler(params.WaitHandler)

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	return cmd, nil
}

func (r *kubeProxyRunner) UpTunnel(localPort int, kubeProxyPort string) (connection.Tunnel, string, error) {
	address := kubeproxy.ExtractTunnelAddressFromEnv(localPort, kubeProxyPort)
	if address == "" {
		address = fmt.Sprintf("127.0.0.1:%s:127.0.0.1:%d", kubeProxyPort, localPort)
	}

	r.client.settings.Logger().DebugContext(context.Background(), fmt.Sprintf("Try up tunnel for kube proxy on %s", address))

	tun := NewTunnel(r.client, address)

	if err := tun.Up(r.ctx); err != nil {
		return nil, address, err
	}

	return tun, address, nil
}

func (r *kubeProxyRunner) ClientID() string {
	return r.client.id
}
