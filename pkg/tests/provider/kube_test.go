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
	"strings"
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/retry"
	"github.com/name212/govalue"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/kube"
	"github.com/deckhouse/lib-connection/pkg/provider"
	"github.com/deckhouse/lib-connection/pkg/ssh"
	sshconfig "github.com/deckhouse/lib-connection/pkg/ssh/config"
	"github.com/deckhouse/lib-connection/pkg/ssh/gossh"
	"github.com/deckhouse/lib-connection/pkg/tests"
)

func TestDefaultKubeProvider(t *testing.T) {
	runTests := []runTest{
		{
			name: "Go",
			mode: sshconfig.Mode{
				ForceModern: true,
			},
		},

		{
			name: "Cli",
			mode: sshconfig.Mode{
				ForceLegacy: true,
			},
		},
	}

	t.Run("OverSSH", func(t *testing.T) {
		t.Run("Client", func(t *testing.T) {
			baseTest := tests.ShouldNewIntegrationTest(
				t,
				t.Name(),
				tests.TestWithParallelRun(false),
			)

			firstContainer := tests.NewTestContainerWrapper(t, baseTest, tests.WithContainerName("first"))
			secondContainer := tests.NewTestContainerWrapper(
				t,
				baseTest,
				tests.WithContainerName("second"),
				tests.WithConnectToContainerNetwork(firstContainer),
			)

			createKINDCluster(t, baseTest, firstContainer, secondContainer)

			t.Run("SimpleGet", func(t *testing.T) {
				for _, rt := range runTests {
					t.Run(rt.name, func(t *testing.T) {
						test := newSubTest(t, rt)

						defaultConfig := connectionConfigForContainer(firstContainer, rt.mode)
						sshProvider := getSSHProvider(test, defaultConfig)
						registerCleanupSSHProvider(t, test, sshProvider)

						kubeProviderConfig := &kube.Config{}
						kubeProvider := getKubeProvider(t, test, kubeProviderConfig, sshProvider)
						registerCleanupKubeProvider(t, test, kubeProvider)

						ctx := context.TODO()

						firstClient, err := kubeProvider.Client(ctx)
						require.NoError(t, err, "first client should be created")

						assertKubeClient(t, test, firstClient, true)

						secondClient, err := kubeProvider.Client(ctx)
						require.NoError(t, err, "second client should be created")

						require.True(t, firstClient == secondClient, "first client should be equal to second client")
					})
				}
			})

			t.Run("GetClientAfterSwitch", func(t *testing.T) {
				for _, rt := range runTests {
					t.Run(rt.name, func(t *testing.T) {
						test := newSubTest(t, rt)

						defaultConfig := connectionConfigForContainer(firstContainer, rt.mode)
						sshProvider := getSSHProvider(test, defaultConfig)
						registerCleanupSSHProvider(t, test, sshProvider)

						kubeProviderConfig := &kube.Config{}
						kubeProvider := getKubeProvider(t, test, kubeProviderConfig, sshProvider)
						registerCleanupKubeProvider(t, test, kubeProvider)

						ctx := context.TODO()

						firstClient, err := kubeProvider.Client(ctx)
						require.NoError(t, err, "first client should be created")

						assertKubeClient(t, test, firstClient, true)

						_, err = sshProvider.SwitchClient(ctx, tests.Session(secondContainer), secondContainer.AgentPrivateKeys())
						require.NoError(t, err, "ssh client should be switched")

						afterSwitchClient, err := kubeProvider.Client(ctx)
						require.NoError(t, err, "after switch client should be created")

						require.False(t, firstClient == afterSwitchClient, "first client should not be equal to second client after switch")

						assertKubeClient(t, test, afterSwitchClient, true)

						_, err = sshProvider.SwitchToDefault(ctx)
						require.NoError(t, err, "ssh client should be switched to default")

						afterSwitchToDefaultClient, err := kubeProvider.Client(ctx)
						require.NoError(t, err, "after switch to default client should be created")

						require.False(t, firstClient == afterSwitchToDefaultClient, "first client should not be equal to second client after switch to default")
						require.False(t, afterSwitchClient == afterSwitchToDefaultClient, "after switch client should not be equal to second client after switch to default")

						assertKubeClient(t, test, afterSwitchToDefaultClient, true)
					})
				}
			})

			t.Run("NewAdditionalClient", func(t *testing.T) {
				for _, rt := range runTests {
					t.Run(rt.name, func(t *testing.T) {
						test := newSubTest(t, rt)

						defaultConfig := connectionConfigForContainer(firstContainer, rt.mode)
						sshProvider := getSSHProvider(test, defaultConfig)
						registerCleanupSSHProvider(t, test, sshProvider)

						kubeProviderConfig := &kube.Config{}
						kubeProvider := getKubeProvider(t, test, kubeProviderConfig, sshProvider)
						registerCleanupKubeProvider(t, test, kubeProvider)

						ctx := context.TODO()

						firstClient, err := kubeProvider.Client(ctx)
						require.NoError(t, err, "first client should be created")

						assertKubeClient(t, test, firstClient, true)

						additionalClients := make([]connection.KubeClient, 0, 2)

						firstAdditionalClient, err := kubeProvider.NewAdditionalClient(ctx)
						require.NoError(t, err, "additional client should be created")
						additionalClients = append(additionalClients, firstAdditionalClient)

						secondAdditionalClient, err := kubeProvider.NewAdditionalClient(ctx)
						require.NoError(t, err, "additional client should be created")
						additionalClients = append(additionalClients, secondAdditionalClient)

						require.Equal(t, kubeProvider.AdditionalClientsCount(), len(additionalClients), "additional client should added to provider")

						assertAdditionalClients(t, test, firstClient, additionalClients)

						_, err = sshProvider.SwitchClient(ctx, tests.Session(secondContainer), secondContainer.AgentPrivateKeys())
						require.NoError(t, err, "ssh client should be switched")

						clientAfterSwitch, err := kubeProvider.Client(ctx)
						require.NoError(t, err, "first client should be created")
						assertKubeClient(t, test, clientAfterSwitch, true)

						firstAdditionalClientAfterSwitch, err := kubeProvider.NewAdditionalClient(ctx)
						require.NoError(t, err, "additional client should be created")
						additionalClients = append(additionalClients, firstAdditionalClientAfterSwitch)

						secondAdditionalClientAfterSwitch, err := kubeProvider.NewAdditionalClient(ctx)
						require.NoError(t, err, "additional client should be created")
						additionalClients = append(additionalClients, secondAdditionalClientAfterSwitch)

						require.Equal(t, kubeProvider.AdditionalClientsCount(), len(additionalClients), "additional client should added to provider")

						assertAdditionalClients(t, test, clientAfterSwitch, additionalClients)

						// stop additional client does not affect another

						stoppedClients := []connection.KubeClient{
							firstAdditionalClient,
							secondAdditionalClientAfterSwitch,
						}

						for _, c := range stoppedClients {
							kube.Stop(c, true)
						}

						assertKubeClient(t, test, clientAfterSwitch, true)

						for _, c := range stoppedClients {
							assertKubeClient(t, test, c, false)
						}

						liveClients := disJoinClients(additionalClients, stoppedClients)
						for _, c := range liveClients {
							assertKubeClient(t, test, c, true)
						}
					})
				}
			})
		})
	})
}

func newSubTest(t *testing.T, rt runTest) *tests.Test {
	return tests.ShouldNewIntegrationTest(t, rt.getName(t), tests.TestWithParallelRun(false))
}

type runTest struct {
	mode sshconfig.Mode
	name string
}

func (r runTest) getName(t *testing.T) string {
	nameParts := strings.Split(t.Name(), "/")
	name := nameParts[len(nameParts)-2]
	return fmt.Sprintf("KubeProvider%s%s", name, r.name)
}

func createKINDCluster(t *testing.T, test *tests.Test, containers ...*tests.TestContainerWrapper) *tests.KINDCluster {
	forKind := make([]*tests.SSHContainersForKind, 0, len(containers))
	for _, container := range containers {
		client := gossh.NewClient(
			context.TODO(),
			test.Settings(),
			tests.Session(container),
			container.AgentPrivateKeys(),
		)

		err := client.Start()
		require.NoError(t, err, "client should start for %s", container.Container.ContainerSettings().ContainerName)

		forKind = append(forKind, &tests.SSHContainersForKind{
			Container: container,
			Client:    client,
		})
	}

	kindCluster := tests.CreateKINDCluster(t, &tests.KINDClusterCreateParams{
		Test:        test,
		ClusterName: "kube-provider-client",
		Containers:  forKind,
	})

	kindCluster.RegisterCleanup(t)

	for _, c := range forKind {
		c.Client.Stop()
	}

	return kindCluster
}

func connectionConfigForContainer(container *tests.TestContainerWrapper, mode sshconfig.Mode) *sshconfig.ConnectionConfig {
	containerPrivateKeys := container.AgentPrivateKeys()
	privateKeys := make([]sshconfig.AgentPrivateKey, 0, len(containerPrivateKeys))
	for _, key := range containerPrivateKeys {
		privateKeys = append(privateKeys, sshconfig.AgentPrivateKey{
			Key:        key.Key,
			Passphrase: key.Passphrase,
			IsPath:     true,
		})
	}

	return &sshconfig.ConnectionConfig{
		Config: &sshconfig.Config{
			Mode: mode,

			User:         container.Settings.Username,
			Port:         tests.Ptr(container.LocalPort()),
			SudoPassword: container.Settings.Password,

			PrivateKeys: privateKeys,
		},

		Hosts: []sshconfig.Host{
			{
				Host: "127.0.0.1",
			},
		},
	}
}

func getSSHProvider(test *tests.Test, config *sshconfig.ConnectionConfig) *provider.DefaultSSHProvider {
	defaultLoopParam := retry.NewEmptyParams(
		retry.WithWait(2*time.Second),
		retry.WithAttempts(10),
	)

	loopsParams := gossh.ClientLoopsParams{
		ConnectToHostDirectly: defaultLoopParam.Clone(),
		NewSession:            defaultLoopParam.Clone(),
	}

	return provider.NewDefaultSSHProvider(
		test.Settings(),
		config,
		provider.SSHClientWithLoopsParams(loopsParams),
		provider.SSHClientWithStartAfterCreate(true),
	)
}

func assertKubeClient(t *testing.T, test *tests.Test, client connection.KubeClient, success bool) {
	const (
		key = "my-key"
		ns  = "default"
	)

	name := fmt.Sprintf("kube-cl-%s", tests.GenerateID(test.Name()))
	content := tests.RandString(32)

	defaultParams := retry.NewEmptyParams(
		retry.WithAttempts(5),
		retry.WithWait(2*time.Second),
		retry.WithLogger(test.GetLogger()),
	)

	createCMParams := defaultParams.Clone(
		retry.WithName("Create ConfigMap %s/%s", ns, name),
	)

	err := retry.NewLoopWithParams(createCMParams).Run(func() error {
		ctx, cancel := kubeRequestCtx()
		defer cancel()

		cm := v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: ns,
			},

			Data: map[string]string{
				key: content,
			},
		}

		_, err := client.CoreV1().ConfigMaps(ns).Create(ctx, &cm, metav1.CreateOptions{})

		return err
	})

	assertError := require.Error
	if success {
		assertError = require.NoError
	}

	assertError(t, err, "should valid create configmap result")

	getCMParams := defaultParams.Clone(
		retry.WithName("Get ConfigMap %s/%s", ns, name),
	)

	var gotCM *v1.ConfigMap
	err = retry.NewLoopWithParams(getCMParams).Run(func() error {
		ctx, cancel := kubeRequestCtx()
		defer cancel()
		cm, err := client.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		gotCM = cm
		return nil
	})

	if success {
		require.NoError(t, err, "should get configmap")
		require.NotNil(t, gotCM, "should get configmap")
		require.Equal(t, content, gotCM.Data[key], "should content be equal")

		return
	}

	require.Error(t, err, "should not get configmap")
}

func kubeRequestCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.TODO(), 4*time.Second)
}

func registerCleanupSSHProvider(t *testing.T, test *tests.Test, p *provider.DefaultSSHProvider) {
	t.Cleanup(func() {
		if err := p.Cleanup(context.TODO()); err != nil {
			test.GetLogger().ErrorF("Failed to clean up %s provider ssh: %v", t.Name(), err)
		}
	})
}

func registerCleanupKubeProvider(t *testing.T, test *tests.Test, p *provider.DefaultKubeProvider) {
	t.Cleanup(func() {
		if err := p.Cleanup(context.TODO()); err != nil {
			test.GetLogger().ErrorF("Failed to clean up %s provider kube provider: %v", t.Name(), err)
		}
	})
}

func getKubeProvider(t *testing.T, test *tests.Test, config *kube.Config, sshProvider connection.SSHProvider) *provider.DefaultKubeProvider {
	sett := test.Settings()
	ri, err := provider.GetRunnerInterface(config, sett, sshProvider)
	require.NoError(t, err, "runner interface should provided")
	return provider.NewDefaultKubeProvider(sett, config, ri)
}

func extractSSHClient(t *testing.T, kubeClient connection.KubeClient) connection.SSHClient {
	kubeClientImpl, ok := kubeClient.(*kube.KubernetesClient)
	require.True(t, ok, "kube client should be of type *kube.KubernetesClient")

	require.False(t, govalue.Nil(kubeClientImpl.NodeInterface), "kube client should have node interface")

	nodeWrapper, ok := kubeClientImpl.NodeInterface.(*ssh.NodeInterfaceWrapper)
	require.True(t, ok, "node wrapper should be of type *ssh.NodeInterfaceWrapper")

	sshClient := nodeWrapper.Client()

	require.False(t, govalue.Nil(sshClient), "ssh client should not be nil")

	return sshClient
}

func assertAdditionalClients(t *testing.T, test *tests.Test, clientFromClientCall connection.KubeClient, additional []connection.KubeClient) {
	sshClientFromClientCall := extractSSHClient(t, clientFromClientCall)

	for i, client := range additional {
		assertKubeClient(t, test, client, true)

		currentSSHClient := extractSSHClient(t, client)
		require.False(t, currentSSHClient == sshClientFromClientCall, "additional ssh client should not be equal to first ssh additional client")

		for _, a := range additional[i+1:] {
			require.False(t, client == a, "additional client should not be equal to additional another client")

			additionalSSHClient := extractSSHClient(t, a)
			require.False(t, additionalSSHClient == currentSSHClient, "additional ssh client should not be equal to additional another client")
		}
	}
}

func disJoinClients(all []connection.KubeClient, subSet []connection.KubeClient) []connection.KubeClient {
	res := make([]connection.KubeClient, 0, len(subSet))
	for _, client := range all {
		contain := false
		for _, sub := range subSet {
			if client == sub {
				contain = true
				break
			}
		}

		if !contain {
			res = append(res, client)
		}
	}

	return res
}
