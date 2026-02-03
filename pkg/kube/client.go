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
	"context"
	"fmt"
	"time"

	// skip linting I do not understand wy golang-ci-lint fail here
	//nolint:goimports
	"github.com/deckhouse/lib-dhctl/pkg/retry"
	//nolint:goimports
	klient "github.com/flant/kube-client/client"
	//nolint:goimports
	"github.com/name212/govalue"
	//nolint:goimports
	"k8s.io/apimachinery/pkg/runtime/schema"
	// oidc allows using oidc provider in kubeconfig
	//nolint:goimports
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh"
	"github.com/deckhouse/lib-connection/pkg/ssh/gossh"
	"github.com/deckhouse/lib-connection/pkg/ssh/local"
)

var (
	_ connection.KubeClient = &KubernetesClient{}
)

type ClientLoopParams struct {
	StartingKubeProxy retry.Params
}

var defaultStartKubeProxyLoopParamsOps = []retry.ParamsBuilderOpt{
	retry.WithWait(1 * time.Second),
}

// KubernetesClient connects to kubernetes API server through ssh tunnel and kubectl proxy.
type KubernetesClient struct {
	connection.KubeClient
	NodeInterface connection.Interface
	KubeProxy     connection.KubeProxy

	loopsParams ClientLoopParams

	settings settings.Settings
}

func NewKubernetesClient(sett settings.Settings) *KubernetesClient {
	return &KubernetesClient{
		settings: sett,
	}
}

func NewFakeKubernetesClient() *KubernetesClient {
	return &KubernetesClient{KubeClient: klient.NewFake(nil)}
}

func NewFakeKubernetesClientWithListGVR(gvr map[schema.GroupVersionResource]string) *KubernetesClient {
	return &KubernetesClient{KubeClient: klient.NewFake(gvr)}
}

func (k *KubernetesClient) WithNodeInterface(client connection.Interface) *KubernetesClient {
	if !govalue.Nil(client) {
		k.NodeInterface = client
	}
	return k
}

func (k *KubernetesClient) WithLoopsParams(p ClientLoopParams) *KubernetesClient {
	k.loopsParams = p
	return k
}

func (k *KubernetesClient) NodeInterfaceAsSSHClient() connection.SSHClient {
	if govalue.Nil(k.NodeInterface) {
		return nil
	}

	cl, ok := k.NodeInterface.(*ssh.NodeInterfaceWrapper)
	if !ok {
		return nil
	}

	return cl.Client()
}

type InitOpts struct {
	NoStartKubeProxy bool
}

type InitOpt func(*InitOpts)

func InitWithNoStartKubeProxy() InitOpt {
	return func(initOpts *InitOpts) {
		initOpts.NoStartKubeProxy = true
	}
}

// Init initializes kubernetes client
// Deprecated:
// use InitContext
// Warning! use InitWithNoStartKubeProxy for only testing purposes
func (k *KubernetesClient) Init(params *Config, opts ...InitOpt) error {
	return k.InitContext(context.Background(), params, opts...)
}

// InitContext
// Warning! use InitWithNoStartKubeProxy for only testing purposes
func (k *KubernetesClient) InitContext(ctx context.Context, params *Config, opts ...InitOpt) error {
	return k.initContext(ctx, params, opts...)
}

func (k *KubernetesClient) initContext(ctx context.Context, params *Config, opts ...InitOpt) error {
	options := &InitOpts{}

	for _, opt := range opts {
		opt(options)
	}

	kubeClient := klient.New()
	kubeClient.WithRateLimiterSettings(30, 60)
	_, isLocalRun := k.NodeInterface.(*local.NodeInterface)

	switch {
	case params.KubeConfigInCluster:
	case params.KubeConfig != "":
		kubeClient.WithContextName(params.KubeConfigContext)
		kubeClient.WithConfigPath(params.KubeConfig)
	case params.RestConfig != nil:
		kubeClient.WithRestConfig(params.RestConfig)
	case isLocalRun:
		if !options.NoStartKubeProxy {
			_, err := k.StartKubernetesProxy(ctx)
			if err != nil {
				return err
			}
		}
	default:
		if !options.NoStartKubeProxy {
			port, err := k.StartKubernetesProxy(ctx)
			if err != nil {
				return err
			}
			kubeClient.WithServer("http://localhost:" + port)
		}
	}

	// Initialize kube client for kube events hooks.
	err := kubeClient.Init()
	if err != nil {
		return fmt.Errorf("initialize kube client: %s", err)
	}

	k.KubeClient = kubeClient
	return nil
}

// StartKubernetesProxy initializes kubectl-proxy on remote host and establishes ssh tunnel to it
func (k *KubernetesClient) StartKubernetesProxy(ctx context.Context) (string, error) {
	wrapper, ok := k.NodeInterface.(*ssh.NodeInterfaceWrapper)
	if !ok {
		return "6445", nil
	}

	port, err := k.startRemoteKubeProxy(ctx, wrapper.Client())

	if err != nil {
		return "", fmt.Errorf("start kube proxy: %s", err)
	}

	return port, nil
}

func (k *KubernetesClient) startRemoteKubeProxy(ctx context.Context, sshCl connection.SSHClient) (string, error) {
	logger := k.settings.Logger()
	startLoopParams := retry.SafeCloneOrNewParams(k.loopsParams.StartingKubeProxy, defaultStartKubeProxyLoopParamsOps...).
		Clone(
			retry.WithName("Starting kube proxy"),
			retry.WithLogger(logger),
			retry.WithAttempts(sshCl.Session().CountHosts()),
		)

	port := ""
	err := retry.NewLoopWithParams(startLoopParams).
		RunContext(ctx, func() error {
			logger.InfoF("Using host %s\n", sshCl.Session().Host())

			k.KubeProxy = sshCl.KubeProxy()
			var err error
			port, err = k.KubeProxy.Start(-1)

			if err != nil {
				sshCl.Session().ChoiceNewHost()
				return fmt.Errorf("start kube proxy: %v", err)
			}

			return nil
		})

	if err != nil {
		return "", err
	}

	logger.InfoF("Proxy started on port %s\n", port)

	return port, nil
}

// Stop
// pass full for fully stop client
// for example if use over ssh full stop client also with stop proxy
// it is safe for call with nil client
func Stop(client connection.KubeClient, full bool) {
	if govalue.Nil(client) {
		return
	}

	kubeClient, ok := client.(*KubernetesClient)
	if !ok {
		return
	}

	if govalue.Nil(kubeClient.KubeProxy) {
		return
	}

	kubeClient.KubeProxy.Stop(-1)

	if full {
		wrapper, ok := kubeClient.NodeInterface.(*ssh.NodeInterfaceWrapper)
		if !ok {
			return
		}

		sshClient := wrapper.Client()
		if _, ok := sshClient.(*gossh.Client); ok {
			sshClient.Stop()
		}
	}
}
