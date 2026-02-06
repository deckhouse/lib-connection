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

package testssh

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/retry"
	"github.com/stretchr/testify/require"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/ssh/clissh"
	sshconfig "github.com/deckhouse/lib-connection/pkg/ssh/config"
	"github.com/deckhouse/lib-connection/pkg/ssh/gossh"
	"github.com/deckhouse/lib-connection/pkg/tests"
	"github.com/deckhouse/lib-connection/pkg/utils/kubeproxy"
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

			assertKubeProxy(t, test, firstProxyPort, false)

			// second proxy start on default but get random port
			secondProxy := client.KubeProxy()
			secondProxyPort, err := secondProxy.Start(-1)
			require.NoError(t, err, "second proxy should start")
			assertGetRandomPort(t, secondProxyPort)

			assertKubeProxy(t, test, secondProxyPort, false)

			// third proxy start on default but get random port
			thirdProxy := client.KubeProxy()
			thirdProxyPort, err := thirdProxy.Start(-1)
			require.NoError(t, err, "second proxy should start")
			assertGetRandomPort(t, thirdProxyPort)

			assertKubeProxy(t, test, thirdProxyPort, false)

			// forth proxy start on custom port
			customPort := 30099
			forthProxy := client.KubeProxy()
			forthProxyPort, err := forthProxy.Start(customPort)
			require.NoError(t, err, "second proxy should start")
			require.Equal(t, fmt.Sprintf("%d", customPort), forthProxyPort, "should start on custom port")

			assertKubeProxy(t, test, forthProxyPort, false)

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
				assertKubeProxy(t, test, port, true)
			}

			notAffected := []string{
				firstProxyPort,
				thirdProxyPort,
			}

			for _, port := range notAffected {
				assertKubeProxy(t, test, port, false)
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

	kindCluster := tests.CreateKINDCluster(t, &tests.KINDClusterCreateParams{
		Test:        test,
		ClusterName: "kube-proxy-general",
		Containers: []*tests.SSHContainersForKind{
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

func assertKubeProxy(t *testing.T, test *tests.Test, localServerPort string, wantError bool) {
	url := fmt.Sprintf("http://127.0.0.1:%s/api/v1/nodes", localServerPort)

	test.GetLogger().InfoF("assert kubeproxy on '%s' want err: %v", url, wantError)

	if wantError {
		dialTo := fmt.Sprintf("127.0.0.1:%s", localServerPort)
		d, err := net.DialTimeout("tcp", dialTo, 5*time.Second)
		if err == nil {
			d.Close()
		}

		require.Error(t, err, "should not reach this host %s", localServerPort)
		return
	}

	requestLoop := retry.NewEmptyParams(
		retry.WithName("Check kube proxy available by %s", url),
		retry.WithAttempts(10),
		retry.WithWait(500*time.Millisecond),
		retry.WithLogger(test.Logger),
	)

	_, err := tests.DoGetRequest(
		url,
		requestLoop,
		tests.NewPrefixLogger(test.Logger).WithPrefix(test.FullName()),
	)

	assert := require.NoError
	if wantError {
		assert = require.Error
	}

	assert(t, err, "check local tunnel. Want error %v", wantError)
}
