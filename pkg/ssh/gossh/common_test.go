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

package gossh

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/retry"
	"github.com/stretchr/testify/require"

	"github.com/deckhouse/lib-connection/pkg/tests"
	kind "github.com/deckhouse/lib-connection/pkg/tests/e2e/kube/kind"
)

func registerStopClient(t *testing.T, sshClient *Client) {
	t.Cleanup(func() {
		sshClient.Stop()
	})
}

// todo mount local directory to container and assert via local exec
func assertFilesViaRemoteRun(t *testing.T, sshClient *Client, cmd string, expectedOutput string) {
	s, err := sshClient.NewSSHSession()
	require.NoError(t, err, "session should start")
	defer sshClient.UnregisterSession(s)
	out, err := s.Output(cmd)
	require.NoError(t, err)
	// out contains a contant of uploaded file, should be equal to testFile contant
	require.Equal(t, expectedOutput, string(out))
}

func startContainerAndClientWithContainer(t *testing.T, test *tests.Test, opts ...tests.TestContainerWrapperSettingsOpts) (*Client, *tests.TestContainerWrapper) {
	container := tests.NewTestContainerWrapper(t, test, opts...)
	sshClient := startClient(t, test, container)

	return sshClient, container
}

func startClient(t *testing.T, test *tests.Test, container *tests.TestContainerWrapper) *Client {
	sess := tests.Session(container)
	keys := container.AgentPrivateKeys()

	defaultLoop := retry.NewEmptyParams(
		retry.WithWait(2*time.Second),
		retry.WithAttempts(7),
	)

	sshSettings := test.Settings()
	sshClient := NewClient(context.Background(), sshSettings, sess, keys).WithLoopsParams(ClientLoopsParams{
		ConnectToBastion:        defaultLoop.Clone(),
		ConnectToHostViaBastion: defaultLoop.Clone(),
		ConnectToHostDirectly:   defaultLoop.Clone(),
		NewSession:              defaultLoop.Clone(),
		CheckReverseTunnel:      defaultLoop.Clone(),
	})

	err := sshClient.Start()
	// expecting no error on client start
	require.NoError(t, err)

	registerStopClient(t, sshClient)

	return sshClient
}

func startContainerAndClient(t *testing.T, test *tests.Test) *Client {
	sshClient, _ := startContainerAndClientWithContainer(t, test)
	return sshClient
}

func newSessionTestLoopParams() ClientLoopsParams {
	return ClientLoopsParams{
		NewSession: retry.NewEmptyParams(
			retry.WithWait(2*time.Second),
			retry.WithAttempts(5),
		),
	}
}

func tunnelAddressString(local, remote int) string {
	localAddr := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", local))
	remoteAddr := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", remote))
	return fmt.Sprintf("%s:%s", remoteAddr, localAddr)
}

func registerStopTunnel(t *testing.T, tunnel *Tunnel) {
	t.Cleanup(func() {
		tunnel.Stop()
	})
}

func startContainerAndClientAndKind(t *testing.T, test *tests.Test, opts ...tests.TestContainerWrapperSettingsOpts) (*Client, *tests.TestContainerWrapper) {
	sshClient, container := startContainerAndClientWithContainer(t, test, opts...)

	kindCluster := kind.CreateKINDCluster(t, &kind.KINDClusterCreateParams{
		Test:        test,
		ClusterName: "kube-proxy",
		Containers: []*kind.SSHContainersForKind{
			{
				Client:    sshClient,
				Container: container,
			},
		},
	})

	kindCluster.RegisterCleanup(t)

	return sshClient, container
}
