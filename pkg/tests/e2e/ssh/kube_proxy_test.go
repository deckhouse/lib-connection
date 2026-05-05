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

package ssh_test

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/retry"
	"github.com/stretchr/testify/require"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/ssh/base/kubeproxy"
	"github.com/deckhouse/lib-connection/pkg/ssh/clissh"
	sshconfig "github.com/deckhouse/lib-connection/pkg/ssh/config"
	"github.com/deckhouse/lib-connection/pkg/ssh/gossh"
	"github.com/deckhouse/lib-connection/pkg/tests"
	kind "github.com/deckhouse/lib-connection/pkg/tests/e2e/kube/kind"
)

func TestKubeProxy(t *testing.T) {
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

	baseTest := tests.ShouldNewIntegrationTest(t, "TestBaseKubeProxy")

	container := startContainerAndKind(t, baseTest)

	assertGetRandomPort := func(t *testing.T, port string) {
		intPort, err := strconv.Atoi(port)
		require.NoError(t, err, "should convert port to int")

		require.True(t, intPort >= 22340, "should port in range %d", intPort)
		require.True(t, intPort <= 22499, "should port in range %d", intPort)
	}

	for _, rt := range runTests {
		t.Run(rt.name, func(t *testing.T) {
			test := tests.ShouldNewIntegrationTest(t, "TestKubeProxy"+rt.name)

			wait := func(op string) {
				test.GetLogger().InfoF("%s", op)
				time.Sleep(10 * time.Second)
			}

			client := startClientForContainer(t, test, rt, container)

			// use default port
			firstProxy := client.KubeProxy()
			firstProxyPort, err := firstProxy.Start(-1)
			require.NoError(t, err, "proxy should start")
			require.Equal(t, fmt.Sprintf("%d", kubeproxy.DefaultLocalAPIPort), firstProxyPort, "should start on default port")

			tests.AssertKubeProxy(t, test, firstProxyPort, false)

			// second proxy start on default but get random port
			secondProxy := client.KubeProxy()
			secondProxyPort, err := secondProxy.Start(-1)
			require.NoError(t, err, "second proxy should start")
			assertGetRandomPort(t, secondProxyPort)

			tests.AssertKubeProxy(t, test, secondProxyPort, false)

			// third proxy start on default but get random port
			thirdProxy := client.KubeProxy()
			thirdProxyPort, err := thirdProxy.Start(-1)
			require.NoError(t, err, "second proxy should start")
			assertGetRandomPort(t, thirdProxyPort)

			tests.AssertKubeProxy(t, test, thirdProxyPort, false)

			// forth proxy start on custom port
			customPort := tests.RandRange(30001, 30199)
			test.GetLogger().InfoF("Got custom Port: %d", customPort)
			forthProxy := client.KubeProxy()
			forthProxyPort, err := forthProxy.Start(customPort)
			require.NoError(t, err, "second proxy should start")
			require.Equal(t, fmt.Sprintf("%d", customPort), forthProxyPort, "should start on custom port")

			tests.AssertKubeProxy(t, test, forthProxyPort, false)

			anotherOnCustomProxy := client.KubeProxy()
			_, err = anotherOnCustomProxy.Start(customPort)
			require.Error(t, err, "proxy should not start at same port")

			secondProxy.Stop(-1)
			forthProxy.Stop(-1)

			wait("stopping proxies")

			stopped := []string{
				forthProxyPort,
				secondProxyPort,
			}

			for _, port := range stopped {
				tests.AssertKubeProxy(t, test, port, true)
			}

			notAffected := []string{
				firstProxyPort,
				thirdProxyPort,
			}

			for _, port := range notAffected {
				tests.AssertKubeProxy(t, test, port, false)
			}
		})
	}
}

func startContainerAndKind(t *testing.T, test *tests.Test, opts ...tests.TestContainerWrapperSettingsOpts) *tests.TestContainerWrapper {
	container := tests.NewTestContainerWrapper(t, test, opts...)

	rt := runTest{
		name: "start kind",
		mode: sshconfig.Mode{
			ForceModern: true,
		},
	}

	kindCluster := kind.CreateKINDCluster(t, &kind.KINDClusterCreateParams{
		Test:        test,
		ClusterName: "kube-proxy-general",
		Containers: []*kind.SSHContainersForKind{
			{
				Client:    startClientForContainer(t, test, rt, container),
				Container: container,
			},
		},
	})

	kindCluster.RegisterCleanup(t)

	return container
}

func startClientForContainer(t *testing.T, test *tests.Test, rt runTest, container *tests.TestContainerWrapper) connection.SSHClient {
	sess := tests.Session(container)
	keys := container.AgentPrivateKeys()

	defaultLoop := retry.NewEmptyParams(
		retry.WithWait(2*time.Second),
		retry.WithAttempts(7),
	)

	sshSettings := test.Settings()
	ctx := context.TODO()

	var sshClient connection.SSHClient

	if rt.mode.ForceModern {
		sshClient = gossh.NewClient(ctx, sshSettings, sess, keys).WithLoopsParams(gossh.ClientLoopsParams{
			ConnectToBastion:        defaultLoop.Clone(),
			ConnectToHostViaBastion: defaultLoop.Clone(),
			ConnectToHostDirectly:   defaultLoop.Clone(),
			NewSession:              defaultLoop.Clone(),
			CheckReverseTunnel:      defaultLoop.Clone(),
		})
	} else {
		sshClient = clissh.NewClient(sshSettings, sess, keys, true)
	}

	err := sshClient.Start()
	// expecting no error on client start
	require.NoError(t, err)

	registerStopClient(t, sshClient)

	return sshClient
}
