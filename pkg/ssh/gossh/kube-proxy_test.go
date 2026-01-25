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
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/retry"
	"github.com/stretchr/testify/require"

	sshtesting "github.com/deckhouse/lib-connection/pkg/ssh/gossh/testing"
)

func TestKubeProxy(t *testing.T) {
	test := sshtesting.ShouldNewTest(t, "TestKubeProxy")

	sshClient, container := startContainerAndClientAndKind(t, test)

	cmd := NewSSHCommand(sshClient, "kubectl", "get", "no")
	out, err := cmd.CombinedOutput(context.Background())
	test.Logger.InfoF("kubectl get no\n%s", out)
	require.NoError(t, err)

	t.Run("Kubeproxy with HealthMonitor", func(t *testing.T) {
		kp := sshClient.KubeProxy()
		port, err := kp.Start(-1)
		require.NoError(t, err)

		checkKubeProxy(t, test, port, false)

		// restart container case
		restartSleep := 5 * time.Second
		err = container.Container.SoftRestart(true, restartSleep)
		require.NoError(t, err)

		// wait for ssh client/tunnel/kubeproxy restart
		time.Sleep(20 * time.Second)
		checkKubeProxy(t, test, port, false)

		// network issue case
		err = container.Container.FailAndUpConnection(restartSleep)
		require.NoError(t, err)

		// wait for ssh client/tunnel/kubeproxy restart
		time.Sleep(20 * time.Second)
		checkKubeProxy(t, test, port, false)

		kp.StopAll()
	})
}

func checkKubeProxy(t *testing.T, test *sshtesting.Test, localServerPort string, wantError bool) {
	url := fmt.Sprintf("http://127.0.0.1:%s/api/v1/nodes", localServerPort)

	requestLoop := retry.NewEmptyParams(
		retry.WithName("Check kube proxy available by %s", url),
		retry.WithAttempts(10),
		retry.WithWait(500*time.Millisecond),
		retry.WithLogger(test.Logger),
	)

	_, err := sshtesting.DoGetRequest(
		url,
		requestLoop,
		sshtesting.NewPrefixLogger(test.Logger).WithPrefix(test.FullName()),
	)

	assert := require.NoError
	if wantError {
		assert = require.Error
	}

	assert(t, err, "check local tunnel. Want error %v", wantError)
}
