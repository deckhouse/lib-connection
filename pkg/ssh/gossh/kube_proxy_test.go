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
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/deckhouse/lib-connection/pkg/ssh/base/kubeproxy"
	"github.com/deckhouse/lib-connection/pkg/tests"
)

func TestKubeProxy(t *testing.T) {
	test := tests.ShouldNewIntegrationTest(t, "TestKubeGoProxy")

	// kube-proxy tests occupy the fixed DefaultLocalAPIPort and the port
	// provider range; serialize them across parallel test binaries
	tests.AcquireGlobalTestLock(t, "kube-proxy")
	// the previous holder may still be tearing its listener down, so wait for
	// the fixed port to drain before we start our own proxy on it
	tests.WaitPortFree(t, kubeproxy.DefaultLocalAPIPort)

	if kindBinEnv := os.Getenv("TEST_KIND_BINARY"); kindBinEnv == "" {
		t.Setenv("TEST_KIND_BINARY", "../../../bin/kind")
	}

	sshClient, container := prepareContainerForTestKubeProxy(t, test)

	waitRestart := func(op string) {
		sleep := 20 * time.Second
		test.GetLogger().InfoContext(context.Background(), fmt.Sprintf("Waiting %s for finish %s", sleep.String(), op))
		time.Sleep(sleep)
	}

	assertPort := func(t *testing.T, got string, expected int) {
		require.Equal(t, fmt.Sprintf("%d", expected), got, "proxy should start with port %d", expected)
	}

	// nolint:prealloc
	excludes := []int{container.LocalPort(), kubeproxy.DefaultLocalAPIPort}

	portForStopProxy := tests.RandPortExclude(excludes)
	excludes = append(excludes, portForStopProxy)
	portForStopClient := tests.RandPortExclude(excludes)

	assertProxyStoppedAndNotRestarted := func(t *testing.T, test *tests.Test) {
		// sett := test.Settings()

		// should be rewritten as well
		// // stop all
		// tests.AssertLogMessagesCount(t, sett, "Proxy command stopped", 1)
		// tests.AssertLogMessagesCount(t, sett, "Tunnel stopped", 1)
		// tests.AssertLogMessagesCount(t, sett, "Kube proxy health monitor started", 1)
		// tests.AssertLogMessagesCount(t, sett, "Kube proxy health monitor stopped", 1)
		// tests.AssertLogMessagesCount(t, sett, "Got kube proxy stopped message", 1)

		// // not restart proxy
		// tests.AssertNoLogMessage(t, sett, "Stopping previous tunnel")
		// tests.AssertNoLogMessage(t, sett, "Tunnel failed. Stopping previous tunnel")
		// tests.AssertNoLogMessage(t, sett, "Tunnel stopped before restart. Starting new tunnel")
		// tests.AssertNoLogMessage(t, sett, "Tunnel re up successfully")
		// tests.AssertNoLogMessage(t, sett, "Try restart kube proxy fully")
		// tests.AssertNoLogMessage(t, sett, "New host selected on fully restart")
	}

	stopClient := func(client *Client) func() {
		return func() {
			client.Stop()
		}
	}

	t.Run("Kube proxy with HealthMonitor", func(t *testing.T) {
		kp := sshClient.KubeProxy()
		port, err := kp.Start(-1)
		require.NoError(t, err, "failed to start kube proxy")
		assertPort(t, port, kubeproxy.DefaultLocalAPIPort)

		tests.AssertKubeProxy(t, test, port, false)

		sshClient.WithID("Restart container")

		// restart container case
		restartSleep := 5 * time.Second
		test.GetLogger().InfoContext(context.Background(), fmt.Sprintf("Restart container with wait %s", restartSleep.String()))
		err = container.Container.SoftRestart(true, restartSleep)
		require.NoError(t, err, "container should restart")

		// wait for ssh client/tunnel/kubeproxy restart
		waitRestart("restart container")
		tests.AssertKubeProxy(t, test, port, false)

		sshClient.WithID("")

		// network issue case
		err = container.Container.FailAndUpConnection(restartSleep)
		require.NoError(t, err)

		// wait for ssh client/tunnel/kubeproxy restart
		waitRestart("network issue")
		tests.AssertKubeProxy(t, test, port, false)

		kp.StopAll()

		waitRestart("stop all")
	})

	t.Run("Stop kube proxy", func(t *testing.T) {
		stopProxyTest := tests.ShouldNewIntegrationTest(t, "TestKubeGoProxyStop")
		sshClientForStopProxy := startClient(t, stopProxyTest, container)

		kp := sshClientForStopProxy.KubeProxy()

		port, err := kp.Start(portForStopProxy)
		require.NoError(t, err, "proxy should start with port %d", portForStopProxy)
		assertPort(t, port, portForStopProxy)

		tests.AssertKubeProxy(t, stopProxyTest, port, false)

		kp.StopAll()

		waitRestart("stop kube proxy")

		tests.AssertKubeProxy(t, stopProxyTest, port, true)

		stopAll := func() {
			kp.StopAll()
		}

		require.NotPanics(t, stopAll, "second StopAll should not panics")

		waitRestart("second stop all")

		assertProxyStoppedAndNotRestarted(t, stopProxyTest)
		// tests.AssertLogMessagesCount(t, stopProxyTest.Settings(), "Stop kube-proxy: kube proxy already stopped. Skip", 1)

		require.NotPanics(t, stopClient(sshClientForStopProxy), "stop client after stop proxy does not panics")
	})

	t.Run("Stop client", func(t *testing.T) {
		stopClientTest := tests.ShouldNewIntegrationTest(t, "TestKubeGoProxyStopClient")
		sshClientForStopClient := startClient(t, stopClientTest, container)

		kp := sshClientForStopClient.KubeProxy()

		port, err := kp.Start(portForStopClient)
		require.NoError(t, err, "proxy should start with port %d", portForStopClient)
		assertPort(t, port, portForStopClient)

		tests.AssertKubeProxy(t, stopClientTest, port, false)

		sshClientForStopClient.Stop()

		waitRestart("stop client")

		tests.AssertKubeProxy(t, stopClientTest, port, true)

		assertProxyStoppedAndNotRestarted(t, stopClientTest)

		require.NotPanics(t, stopClient(sshClientForStopClient), "second stop client does not panics")
	})
}

func prepareContainerForTestKubeProxy(t *testing.T, test *tests.Test) (*Client, *tests.TestContainerWrapper) {
	sshClient, container := startContainerAndClientAndKind(t, test)

	test.GetLogger().InfoContext(context.Background(), "Try to check run kubectl on ssh container...")
	cmd := NewSSHCommand(sshClient, "kubectl", "get", "no")
	out, err := cmd.CombinedOutput(context.Background())
	test.Logger.InfoContext(context.Background(), fmt.Sprintf("kubectl get no\n%s", out))
	require.NoError(t, err)

	return sshClient, container
}
