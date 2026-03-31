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
	"github.com/deckhouse/lib-connection/pkg/ssh/clissh"
	sshconfig "github.com/deckhouse/lib-connection/pkg/ssh/config"
	"github.com/deckhouse/lib-connection/pkg/ssh/gossh"
	"github.com/deckhouse/lib-connection/pkg/tests"
)

func TestDefaultKubeProvider(t *testing.T) {
	cliRunTest := runTest{
		name: "Cli",
		mode: sshconfig.Mode{
			ForceLegacy: true,
		},
	}

	runTests := []runTest{
		{
			name: "Go",
			mode: sshconfig.Mode{
				ForceModern: true,
			},
		},

		cliRunTest,
	}

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

	kindCluster := createKINDCluster(t, baseTest, firstContainer, secondContainer)

	t.Run("OverSSH", func(t *testing.T) {
		t.Run("Client", func(t *testing.T) {
			t.Run("SimpleGet", func(t *testing.T) {
				for _, rt := range runTests {
					t.Run(rt.name, func(t *testing.T) {
						test := newSubTest(t, rt)

						defaultConfig := connectionConfigForContainer(firstContainer, rt.mode)
						sshProvider := getSSHProvider(test, defaultConfig)
						registerCleanupSSHProvider(t, test, sshProvider)

						kubeProviderConfig := &kube.Config{}
						kubeProvider, _ := getKubeProvider(t, test, kubeProviderConfig, sshProvider)
						registerCleanupKubeProvider(t, test, kubeProvider)

						clients := assertSimpleGetKubeClient(t, test, kubeProvider)

						sshClients := make([]connection.SSHClient, 0, len(clients))
						for _, c := range clients {
							sshClients = append(sshClients, extractSSHClient(t, c))
						}

						for i, client := range sshClients {
							for _, a := range sshClients[i+1:] {
								require.True(t, a == client, "ssh clients should be same")
							}
						}
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
						kubeProvider, runnerIface := getKubeProvider(t, test, kubeProviderConfig, sshProvider)
						registerCleanupKubeProvider(t, test, kubeProvider)

						ctx := context.TODO()

						firstClient, err := kubeProvider.Client(ctx)
						require.NoError(t, err, "first client should be created")

						assertKubeClient(t, test, firstClient, true)

						firstSSHClient := extractSSHClient(t, firstClient)

						logClientSwitching(test)
						_, err = sshProvider.SwitchClient(ctx, tests.Session(secondContainer), secondContainer.AgentPrivateKeys())
						require.NoError(t, err, "ssh client should be switched")

						// should use custom port for assert that client after switch stopped
						provider.RunnerInterfaceWithInitOpts(kube.InitWithLocalPort(tests.RandPort()))(runnerIface)

						afterSwitchClient, err := kubeProvider.Client(ctx)
						require.NoError(t, err, "after switch client should be created")

						require.False(t, firstClient == afterSwitchClient, "first client should not be equal to second client after switch")

						assertKubeClient(t, test, afterSwitchClient, true)
						assertKubeClient(t, test, firstClient, false)

						afterSwitchSSHClient := extractSSHClient(t, afterSwitchClient)
						require.False(t, firstSSHClient == afterSwitchSSHClient, "first ssh client should not be equal to second client after switch")

						logClientSwitching(test)
						_, err = sshProvider.SwitchToDefault(ctx)
						require.NoError(t, err, "ssh client should be switched to default")

						// should use custom port for assert that client after switch stopped
						provider.RunnerInterfaceWithInitOpts(kube.InitWithLocalPort(tests.RandPort()))(runnerIface)

						afterSwitchToDefaultClient, err := kubeProvider.Client(ctx)
						require.NoError(t, err, "after switch to default client should be created")

						require.False(t, firstClient == afterSwitchToDefaultClient, "first client should not be equal to second client after switch to default")
						require.False(t, afterSwitchClient == afterSwitchToDefaultClient, "after switch client should not be equal to second client after switch to default")

						assertKubeClient(t, test, afterSwitchToDefaultClient, true)
						assertKubeClient(t, test, afterSwitchClient, false)

						afterSwitchToDefaultSSHClient := extractSSHClient(t, afterSwitchToDefaultClient)
						require.False(t, firstSSHClient == afterSwitchToDefaultSSHClient, "first SSH client should not be equal to after switch to default SSH client")
						require.False(t, afterSwitchSSHClient == afterSwitchToDefaultSSHClient, "after switch SSH client should not be equal to after switch to default SSH client")
					})
				}
			})
		})

		t.Run("NewAdditionalClient", func(t *testing.T) {
			for _, rt := range runTests {
				t.Run(rt.name, func(t *testing.T) {
					test := newSubTest(t, rt)

					defaultConfig := connectionConfigForContainer(firstContainer, rt.mode)
					sshProvider := getSSHProvider(test, defaultConfig)
					registerCleanupSSHProvider(t, test, sshProvider)

					kubeProviderConfig := &kube.Config{}
					kubeProvider, _ := getKubeProvider(t, test, kubeProviderConfig, sshProvider)
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

					assertAdditionalClientsOverSSH(t, test, firstClient, additionalClients, true)

					logClientSwitching(test)
					sshProvider.WithID(rt.getName(t) + "AfterSwitch")
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

					assertAdditionalClientsOverSSH(t, test, clientAfterSwitch, additionalClients, true)

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
						assertSSHClientLive(t, test, extractSSHClient(t, c), false)
					}

					liveClients := disJoinClients(additionalClients, stoppedClients)
					for _, c := range liveClients {
						assertKubeClient(t, test, c, true)
					}

					assertSSHClientLive(t, test, extractSSHClient(t, clientAfterSwitch), true)
				})
			}
		})

		t.Run("NewAdditionalClientWithoutInitialize", func(t *testing.T) {
			for _, rt := range runTests {
				t.Run(rt.name, func(t *testing.T) {
					test := newSubTest(t, rt)

					defaultConfig := connectionConfigForContainer(firstContainer, rt.mode)
					sshProvider := getSSHProvider(test, defaultConfig)
					registerCleanupSSHProvider(t, test, sshProvider)

					kubeProviderConfig := &kube.Config{}
					kubeProvider, _ := getKubeProvider(t, test, kubeProviderConfig, sshProvider)
					registerCleanupKubeProvider(t, test, kubeProvider)

					assertNewAdditionalClientsWithoutInitialize(t, test, kubeProvider, assertAdditionalClientsOverSSH)
				})
			}
		})

		t.Run("FailAdditionalChecks", func(t *testing.T) {
			// test only cli because go-ssh will fail on start
			// cli ssh always create client but it can connect after creation

			test := newSubTest(t, cliRunTest)

			defaultConfig := connectionConfigForContainer(firstContainer, cliRunTest.mode)
			defaultConfig.Config.Port = tests.Ptr(tests.RandPort())
			sshProvider := getSSHProvider(test, defaultConfig)
			registerCleanupSSHProvider(t, test, sshProvider)

			kubeProviderConfig := &kube.Config{}
			kubeProvider, _ := getKubeProvider(t, test, kubeProviderConfig, sshProvider,
				provider.RunnerInterfaceWithSSHLoopsParams(provider.RunnerInterfaceSSHLoopsParams{
					AwaitAvailabilityOverSSH: retry.NewEmptyParams(
						retry.WithWait(2*time.Second),
						retry.WithAttempts(4),
					),
				}),
			)
			registerCleanupKubeProvider(t, test, kubeProvider)

			ctx := context.TODO()

			assertError := func(t *testing.T, err error) {
				require.Error(t, err, "first client should be created")
				require.Contains(t, err.Error(), "SSH connect failed to")
			}

			_, err := kubeProvider.Client(ctx)
			assertError(t, err)

			_, err = kubeProvider.NewAdditionalClient(ctx)
			assertError(t, err)

			require.Len(t, sshProvider.AdditionalClients(), 1, "additional ssh clients should added to provider")

			_, err = kubeProvider.NewAdditionalClientWithoutInitialize(ctx)
			require.NoError(t, err, "client without initialize should be provided")

			require.Len(t, sshProvider.AdditionalClients(), 2, "additional ssh clients should added to provider")
		})

		t.Run("Cleanup", func(t *testing.T) {
			getKubeForCleanupProvider := func(t *testing.T, test *tests.Test, rt runTest) *provider.DefaultKubeProvider {
				defaultConfig := connectionConfigForContainer(firstContainer, rt.mode)
				sshProvider := getSSHProvider(test, defaultConfig)
				registerCleanupSSHProvider(t, test, sshProvider)

				kubeProviderConfig := &kube.Config{}
				kubeProvider, _ := getKubeProvider(t, test, kubeProviderConfig, sshProvider)
				registerCleanupKubeProvider(t, test, kubeProvider)

				return kubeProvider
			}

			t.Run("NoClients", func(t *testing.T) {
				rt := runTest{name: "none"}
				test := newSubTest(t, rt)

				kubeProvider := getKubeForCleanupProvider(t, test, rt)

				doClean := func() {
					err := kubeProvider.Cleanup(context.TODO())
					require.NoError(t, err, "should cleanup")
				}

				require.NotPanics(t, doClean, "should cleanup")
			})

			t.Run("OnlyDefault", func(t *testing.T) {
				for _, rt := range runTests {
					t.Run(rt.name, func(t *testing.T) {
						test := newSubTest(t, rt)

						kubeProvider := getKubeForCleanupProvider(t, test, rt)

						defaultClient, err := kubeProvider.Client(context.TODO())
						require.NoError(t, err, "should be created")

						sshClient := extractSSHClient(t, defaultClient)

						doClean := func() {
							err := kubeProvider.Cleanup(context.TODO())
							require.NoError(t, err, "should cleanup")
						}

						require.NotPanics(t, doClean, "should cleanup")

						require.False(t, kubeProvider.HasCurrent(), "should not have current")
						assertSSHClientLive(t, test, sshClient, true)
					})
				}
			})

			t.Run("WithAdditionals", func(t *testing.T) {
				for _, rt := range runTests {
					t.Run(rt.name, func(t *testing.T) {
						test := newSubTest(t, rt)

						defaultConfig := connectionConfigForContainer(firstContainer, rt.mode)
						sshProvider := getSSHProvider(test, defaultConfig)
						registerCleanupSSHProvider(t, test, sshProvider)

						kubeProviderConfig := &kube.Config{}
						kubeProvider, _ := getKubeProvider(t, test, kubeProviderConfig, sshProvider)
						registerCleanupKubeProvider(t, test, kubeProvider)

						ctx := context.TODO()

						defaultClient, err := kubeProvider.Client(ctx)
						require.NoError(t, err, "should be created")

						additionalClients := make([]connection.KubeClient, 0, 3)

						firstAdditional, err := kubeProvider.NewAdditionalClient(ctx)
						require.NoError(t, err, "additional client should be created")
						additionalClients = append(additionalClients, firstAdditional)

						secondAdditional, err := kubeProvider.NewAdditionalClient(ctx)
						require.NoError(t, err, "additional client should be created")
						additionalClients = append(additionalClients, secondAdditional)

						noInitClient, err := kubeProvider.NewAdditionalClientWithoutInitialize(ctx)
						require.NoError(t, err, "additional client should be created")

						sshClient := extractSSHClient(t, defaultClient)

						doClean := func() {
							err := kubeProvider.Cleanup(context.TODO())
							require.NoError(t, err, "should cleanup")
						}

						require.NotPanics(t, doClean, "should cleanup")

						require.False(t, kubeProvider.HasCurrent(), "should not have current")
						assertSSHClientLive(t, test, sshClient, true)

						require.Equal(t, 0, kubeProvider.AdditionalClientsCount(), "additional client should removed")

						for _, c := range additionalClients {
							assertKubeClient(t, test, c, false)
							assertSSHClientLive(t, test, extractSSHClient(t, c), false)
						}

						assertSSHClientLive(t, test, extractSSHClient(t, noInitClient), false)
					})
				}
			})
		})
	})

	t.Run("OverKubeconfig", func(t *testing.T) {
		rt := runTest{name: "overKubeconfig"}

		getKubeconfigKubeProviderWithPort := func(t *testing.T, test *tests.Test, kind *tests.KINDCluster, port string) (*provider.DefaultKubeProvider, *provider.DefaultSSHProvider) {
			defaultConfig := connectionConfigForContainer(firstContainer, rt.mode)
			sshProvider := getSSHProvider(test, defaultConfig)
			registerCleanupSSHProvider(t, test, sshProvider)

			kubeConfig := kind.KubeconfigWithIP("127.0.0.1", port)

			path := test.MustCreateTmpFile(t, kubeConfig, false, "kube-config.yaml")

			kubeProviderConfig := &kube.Config{
				KubeConfig: path,
			}

			kubeProvider, _ := getKubeProvider(t, test, kubeProviderConfig, sshProvider)
			registerCleanupKubeProvider(t, test, kubeProvider)

			return kubeProvider, sshProvider
		}

		getKubeconfigKubeProvider := func(t *testing.T, test *tests.Test, kind *tests.KINDCluster) (*provider.DefaultKubeProvider, *provider.DefaultSSHProvider) {
			return getKubeconfigKubeProviderWithPort(t, test, kind, kind.ControlPlanePort)
		}

		t.Run("Client", func(t *testing.T) {
			t.Run("SimpleGet", func(t *testing.T) {
				test := newSubTest(t, rt)

				kubeProvider, sshProvider := getKubeconfigKubeProvider(t, test, kindCluster)

				assertSimpleGetKubeClient(t, test, kubeProvider)

				assertNoGetSSHConnection(t, sshProvider)
			})
		})

		t.Run("NewAdditionalClient", func(t *testing.T) {
			test := newSubTest(t, rt)

			kubeProvider, sshProvider := getKubeconfigKubeProvider(t, test, kindCluster)

			assertNewAdditional(t, test, kubeProvider)

			assertNoGetSSHConnection(t, sshProvider)
		})

		t.Run("NewAdditionalClientWithoutInitialize", func(t *testing.T) {
			test := newSubTest(t, rt)

			kubeProvider, sshProvider := getKubeconfigKubeProvider(t, test, kindCluster)
			assertNewAdditionalClientsWithoutInitialize(t, test, kubeProvider, assertAdditionalClients)

			assertNoGetSSHConnection(t, sshProvider)
		})

		t.Run("WithIncorrectConfig", func(t *testing.T) {
			test := newSubTest(t, rt)

			assertIncorrectConfiguration(t, test, func(t *testing.T, test *tests.Test) *provider.DefaultKubeProvider {
				port := fmt.Sprintf("%d", tests.RandPort())
				kubeProvider, _ := getKubeconfigKubeProviderWithPort(t, test, kindCluster, port)
				return kubeProvider
			})
		})

		t.Run("Cleanup", func(t *testing.T) {
			assertCleanupWithoutSSH(t, func(t *testing.T, test *tests.Test) *provider.DefaultKubeProvider {
				kubeProvider, _ := getKubeconfigKubeProvider(t, test, kindCluster)
				return kubeProvider
			})
		})
	})

	t.Run("OverRESTConfig", func(t *testing.T) {
		rt := runTest{name: "overRESTKubeconfig"}

		getKubeconfigKubeProvider := func(t *testing.T, test *tests.Test, kind *tests.KINDCluster, token ...string) (*provider.DefaultKubeProvider, *provider.DefaultSSHProvider) {
			defaultConfig := connectionConfigForContainer(firstContainer, rt.mode)
			sshProvider := getSSHProvider(test, defaultConfig)
			registerCleanupSSHProvider(t, test, sshProvider)

			restConfig, err := kind.RESTConfig()
			require.NoError(t, err, "rest config should be created")

			if len(token) > 0 {
				restConfig.BearerToken = token[0]
			}

			kubeProviderConfig := &kube.Config{
				RestConfig: restConfig,
			}

			kubeProvider, _ := getKubeProvider(t, test, kubeProviderConfig, sshProvider)
			registerCleanupKubeProvider(t, test, kubeProvider)

			return kubeProvider, sshProvider
		}

		t.Run("Client", func(t *testing.T) {
			t.Run("SimpleGet", func(t *testing.T) {
				test := newSubTest(t, rt)

				kubeProvider, sshProvider := getKubeconfigKubeProvider(t, test, kindCluster)

				assertSimpleGetKubeClient(t, test, kubeProvider)

				assertNoGetSSHConnection(t, sshProvider)
			})
		})

		t.Run("NewAdditionalClient", func(t *testing.T) {
			test := newSubTest(t, rt)

			kubeProvider, sshProvider := getKubeconfigKubeProvider(t, test, kindCluster)

			assertNewAdditional(t, test, kubeProvider)

			assertNoGetSSHConnection(t, sshProvider)
		})

		t.Run("NewAdditionalClientWithoutInitialize", func(t *testing.T) {
			test := newSubTest(t, rt)

			kubeProvider, sshProvider := getKubeconfigKubeProvider(t, test, kindCluster)
			assertNewAdditionalClientsWithoutInitialize(t, test, kubeProvider, assertAdditionalClients)

			assertNoGetSSHConnection(t, sshProvider)
		})

		t.Run("WithIncorrectConfig", func(t *testing.T) {
			test := newSubTest(t, rt)

			assertIncorrectConfiguration(t, test, func(t *testing.T, test *tests.Test) *provider.DefaultKubeProvider {
				token := tests.RandString(24)
				kubeProvider, _ := getKubeconfigKubeProvider(t, test, kindCluster, token)
				return kubeProvider
			})
		})

		t.Run("Cleanup", func(t *testing.T) {
			assertCleanupWithoutSSH(t, func(t *testing.T, test *tests.Test) *provider.DefaultKubeProvider {
				kubeProvider, _ := getKubeconfigKubeProvider(t, test, kindCluster)
				return kubeProvider
			})
		})
	})

	t.Run("LocalRun", func(t *testing.T) {
		rt := runTest{name: "local_run"}

		getKubeconfigKubeProvider := func(t *testing.T, test *tests.Test, kind *tests.KINDCluster, rewriteEnv ...string) *provider.DefaultKubeProvider {
			path := ""

			if len(rewriteEnv) > 0 {
				path = rewriteEnv[0]
			} else {
				kubeConfig := kind.Kubeconfig()
				path = test.MustCreateTmpFile(t, kubeConfig, false, "local-kube-config.yaml")
			}

			tests.SetEnvs(t, map[string]string{
				"KUBECONFIG": path,
			})

			kubeProviderConfig := &kube.Config{
				LocalKubeClient: true,
			}

			kubeProvider, _ := getKubeProvider(t, test, kubeProviderConfig, nil)
			registerCleanupKubeProvider(t, test, kubeProvider)

			return kubeProvider
		}

		t.Run("Client", func(t *testing.T) {
			t.Run("SimpleGet", func(t *testing.T) {
				test := newSubTest(t, rt)

				kubeProvider := getKubeconfigKubeProvider(t, test, kindCluster)

				assertSimpleGetKubeClient(t, test, kubeProvider)
			})
		})

		t.Run("NewAdditionalClient", func(t *testing.T) {
			test := newSubTest(t, rt)

			kubeProvider := getKubeconfigKubeProvider(t, test, kindCluster)

			assertNewAdditional(t, test, kubeProvider)
		})

		t.Run("NewAdditionalClientWithoutInitialize", func(t *testing.T) {
			test := newSubTest(t, rt)

			kubeProvider := getKubeconfigKubeProvider(t, test, kindCluster)
			assertNewAdditionalClientsWithoutInitialize(t, test, kubeProvider, assertAdditionalClients)
		})

		t.Run("WithIncorrectConfig", func(t *testing.T) {
			test := newSubTest(t, rt)

			assertIncorrectConfiguration(t, test, func(t *testing.T, test *tests.Test) *provider.DefaultKubeProvider {
				path := "/tmp/not-exist-ewde"
				kubeProvider := getKubeconfigKubeProvider(t, test, kindCluster, path)
				return kubeProvider
			})
		})

		t.Run("Cleanup", func(t *testing.T) {
			assertCleanupWithoutSSH(t, func(t *testing.T, test *tests.Test) *provider.DefaultKubeProvider {
				return getKubeconfigKubeProvider(t, test, kindCluster)
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
	loopsParams := gossh.ClientLoopsParams{
		ConnectToHostDirectly: retry.NewEmptyParams(
			retry.WithWait(2*time.Second),
			retry.WithAttempts(10),
		),
		NewSession: retry.NewEmptyParams(
			retry.WithWait(1*time.Second),
			retry.WithAttempts(5),
		),
	}

	return provider.NewDefaultSSHProvider(
		test.Settings(),
		config,
		provider.SSHClientWithLoopsParams(loopsParams),
		provider.SSHClientWithStartAfterCreate(true),
		provider.SSHClientWithID(test.FullName()),
	)
}

func assertKubeClient(t *testing.T, test *tests.Test, client connection.KubeClient, success bool, errs ...string) {
	const (
		key = "my-key"
		ns  = "default"
	)

	name := fmt.Sprintf("kube-cl-%s", tests.GenerateID(test.Name()))
	content := tests.RandString(32)

	liveLoopParams := retry.NewEmptyParams(
		retry.WithWait(1*time.Second),
		retry.WithAttempts(4),
	)

	liveCtx := context.TODO()
	err := kube.IsLive(liveCtx, client, liveLoopParams)
	if !success {
		require.Error(t, err, "should not live")
		for _, errSub := range errs {
			require.Contains(t, err.Error(), errSub, "should contain %s", errSub)
		}
		return
	}
	require.NoError(t, err, "should live")

	defaultParams := retry.NewEmptyParams(
		retry.WithAttempts(4),
		retry.WithWait(2*time.Second),
		retry.WithLogger(test.GetLogger()),
	)

	createCMParams := defaultParams.Clone(
		retry.WithName("Create ConfigMap %s/%s", ns, name),
	)

	err = retry.NewLoopWithParams(createCMParams).Run(func() error {
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

	require.NoError(t, err, "should create configmap")

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

	require.NoError(t, err, "should get configmap")
	require.NotNil(t, gotCM, "should get configmap")
	require.Equal(t, content, gotCM.Data[key], "should content be equal")
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

func getKubeProvider(t *testing.T, test *tests.Test, config *kube.Config, sshProvider connection.SSHProvider, opts ...provider.RunnerInterfaceOpt) (*provider.DefaultKubeProvider, provider.RunnerInterface) {
	sett := test.Settings()

	initializer := provider.NewSimpleSSHProviderInitializer(sshProvider)

	ri, err := provider.GetRunnerInterface(context.TODO(), config, sett, initializer, opts...)
	require.NoError(t, err, "runner interface should provided")

	loopParams := retry.NewEmptyParams(
		retry.WithAttempts(10),
		retry.WithWait(2*time.Second),
	)

	return provider.NewDefaultKubeProvider(sett, config, ri).WithLoopsParams(provider.KubeProviderLoopsParams{
		InitClient:   loopParams.Clone(),
		WaitingReady: loopParams.Clone(),
	}), ri
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

func assertAdditionalClientsOverSSH(t *testing.T, test *tests.Test, clientFromClientCall connection.KubeClient, additional []connection.KubeClient, success bool) {
	sshClientFromClientCall := extractSSHClient(t, clientFromClientCall)

	for i, client := range additional {
		require.False(t, clientFromClientCall == client, "additional client should not be default")

		assertKubeClient(t, test, client, success)

		currentSSHClient := extractSSHClient(t, client)
		require.False(t, currentSSHClient == sshClientFromClientCall, "additional ssh client should not be equal to first ssh additional client")

		for _, a := range additional[i+1:] {
			require.False(t, client == a, "additional client should not be equal to additional another client")

			additionalSSHClient := extractSSHClient(t, a)
			require.False(t, additionalSSHClient == currentSSHClient, "additional ssh client should not be equal to additional another client")
		}
	}
}

func assertAdditionalClients(t *testing.T, test *tests.Test, clientFromClientCall connection.KubeClient, additional []connection.KubeClient, success bool) {
	for i, client := range additional {
		require.False(t, clientFromClientCall == client, "additional client should not be default")

		assertKubeClient(t, test, client, success)

		for _, a := range additional[i+1:] {
			require.False(t, client == a, "additional client should not be equal to additional another client")
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

func assertSSHClientLive(t *testing.T, test *tests.Test, sshClient connection.SSHClient, live bool) {
	if _, ok := sshClient.(*clissh.Client); ok {
		test.GetLogger().InfoF("SSH client always should be live")
		live = true
	}

	loopParams := retry.NewEmptyParams(
		retry.WithAttempts(3),
		retry.WithWait(2*time.Second),
		retry.WithLogger(test.GetLogger()),
		retry.WithName("Check that ssh client live"),
	)

	out := ""

	err := retry.NewLoopWithParams(loopParams).Run(func() error {
		cmd := sshClient.Command("echo", "-n", "RUN_OK")
		o, err := cmd.CombinedOutput(context.TODO())
		if err != nil {
			return err
		}

		out = string(o)
		return nil
	})

	if !live {
		require.Error(t, err, "ssh client should not be live")
		return
	}

	require.NoError(t, err, "ssh client should live")
	require.True(t, strings.HasSuffix(out, "RUN_OK"), "should valid output for check live")
}

func logClientSwitching(test *tests.Test) {
	test.GetLogger().InfoF("Start switching ssh client")
}

func assertNoGetSSHConnection(t *testing.T, sshProvider *provider.DefaultSSHProvider) {
	require.False(t, sshProvider.HasCurrent(), "ssh provider should not have current client")
	require.Len(t, sshProvider.AdditionalClients(), 0, "ssh provider should not have any additional clients")
}

func assertSimpleGetKubeClient(t *testing.T, test *tests.Test, kubeProvider *provider.DefaultKubeProvider) []connection.KubeClient {
	ctx := context.TODO()

	firstClient, err := kubeProvider.Client(ctx)
	require.NoError(t, err, "first client should be created")

	assertKubeClient(t, test, firstClient, true)

	secondClient, err := kubeProvider.Client(ctx)
	require.NoError(t, err, "second client should be created")

	require.True(t, firstClient == secondClient, "first client should be equal to second client")

	return []connection.KubeClient{firstClient, secondClient}
}

type assertAdditional func(t *testing.T, test *tests.Test, clientFromClientCall connection.KubeClient, additional []connection.KubeClient, success bool)

func assertNewAdditionalClientsWithoutInitialize(t *testing.T, test *tests.Test, kubeProvider *provider.DefaultKubeProvider, assert assertAdditional) {
	ctx := context.TODO()

	firstClient, err := kubeProvider.Client(ctx)
	require.NoError(t, err, "first client should be created")

	assertKubeClient(t, test, firstClient, true)

	additionalClients := make([]connection.KubeClient, 0, 2)

	firstAdditionalClient, err := kubeProvider.NewAdditionalClientWithoutInitialize(ctx)
	require.NoError(t, err, "additional client should be created")
	additionalClients = append(additionalClients, firstAdditionalClient)

	secondAdditionalClient, err := kubeProvider.NewAdditionalClientWithoutInitialize(ctx)
	require.NoError(t, err, "additional client should be created")
	additionalClients = append(additionalClients, secondAdditionalClient)

	require.Equal(t, kubeProvider.AdditionalClientsCount(), len(additionalClients), "additional client should added to provider")

	assert(t, test, firstClient, additionalClients, false)

	// stop additional client no initialized not failed does not affect another
	for _, c := range additionalClients {
		kube.Stop(c, true)
	}

	assertKubeClient(t, test, firstClient, true)
}

type getProvidersWithoutSSH func(t *testing.T, test *tests.Test) *provider.DefaultKubeProvider

func assertCleanupWithoutSSH(t *testing.T, getKubeForCleanupProvider getProvidersWithoutSSH) {
	rt := runTest{name: "cleanup"}

	assertClean := func(t *testing.T, kubeProvider *provider.DefaultKubeProvider) {
		doClean := func() {
			err := kubeProvider.Cleanup(context.TODO())
			require.NoError(t, err, "should cleanup")
		}

		require.NotPanics(t, doClean, "should cleanup")
		require.False(t, kubeProvider.HasCurrent(), "should not have current")
		require.Equal(t, 0, kubeProvider.AdditionalClientsCount(), "should not have any additional clients")
	}

	t.Run("NoClients", func(t *testing.T) {
		test := newSubTest(t, rt)

		kubeProvider := getKubeForCleanupProvider(t, test)

		assertClean(t, kubeProvider)
	})

	t.Run("OnlyDefault", func(t *testing.T) {
		test := newSubTest(t, rt)

		kubeProvider := getKubeForCleanupProvider(t, test)

		defaultClient, err := kubeProvider.Client(context.TODO())
		require.NoError(t, err, "should be created")

		assertClean(t, kubeProvider)

		assertKubeClient(t, test, defaultClient, false, kube.ErrStoppedKubeClient.Error())
	})

	t.Run("WithAdditional", func(t *testing.T) {
		test := newSubTest(t, rt)

		kubeProvider := getKubeForCleanupProvider(t, test)

		ctx := context.TODO()

		defaultClient, err := kubeProvider.Client(ctx)
		require.NoError(t, err, "should be created")

		additionalClients := make([]connection.KubeClient, 0, 3)

		firstAdditional, err := kubeProvider.NewAdditionalClient(ctx)
		require.NoError(t, err, "additional client should be created")
		additionalClients = append(additionalClients, firstAdditional)

		secondAdditional, err := kubeProvider.NewAdditionalClient(ctx)
		require.NoError(t, err, "additional client should be created")
		additionalClients = append(additionalClients, secondAdditional)

		_, err = kubeProvider.NewAdditionalClientWithoutInitialize(ctx)
		require.NoError(t, err, "additional client should be created")

		assertClean(t, kubeProvider)

		assertKubeClient(t, test, defaultClient, false)

		for _, c := range additionalClients {
			assertKubeClient(t, test, c, false)
		}
	})
}

func assertIncorrectConfiguration(t *testing.T, test *tests.Test, getKubeProvider getProvidersWithoutSSH) {
	kubeProvider := getKubeProvider(t, test)

	ctx := context.TODO()

	kubeProvider.WithLoopsParams(provider.KubeProviderLoopsParams{
		WaitingReady: retry.NewEmptyParams(
			retry.WithWait(2*time.Second),
			retry.WithAttempts(4),
		),
	})

	_, err := kubeProvider.Client(ctx)
	require.Error(t, err, "should be not created")

	_, err = kubeProvider.NewAdditionalClient(ctx)
	require.Error(t, err, "additional client should not be created")

	_, err = kubeProvider.NewAdditionalClient(ctx)
	require.Error(t, err, "additional client should not be created")

	_, err = kubeProvider.NewAdditionalClientWithoutInitialize(ctx)
	require.NoError(t, err, "additional client without initialize should be created")

	require.Equal(t, kubeProvider.AdditionalClientsCount(), 1, "only without initialize should store")
}

func assertNewAdditional(t *testing.T, test *tests.Test, kubeProvider *provider.DefaultKubeProvider) {
	ctx := context.TODO()

	defaultClient, err := kubeProvider.Client(ctx)
	require.NoError(t, err, "default client should be created")

	assertKubeClient(t, test, defaultClient, true)

	additionalClients := make([]connection.KubeClient, 0, 2)

	firstAdditionalClient, err := kubeProvider.NewAdditionalClient(ctx)
	require.NoError(t, err, "additional client should be created")
	additionalClients = append(additionalClients, firstAdditionalClient)

	secondAdditionalClient, err := kubeProvider.NewAdditionalClient(ctx)
	require.NoError(t, err, "additional client should be created")
	additionalClients = append(additionalClients, secondAdditionalClient)

	require.Equal(t, len(additionalClients), kubeProvider.AdditionalClientsCount())

	assertAdditionalClients(t, test, defaultClient, additionalClients, true)

	kube.Stop(secondAdditionalClient, true)
	assertKubeClient(t, test, secondAdditionalClient, false, kube.ErrStoppedKubeClient.Error())

	assertKubeClient(t, test, defaultClient, true)
	assertKubeClient(t, test, firstAdditionalClient, true)
}
