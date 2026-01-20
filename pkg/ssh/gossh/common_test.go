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
	"regexp"
	"strings"
	"testing"
	"time"

	sshtesting "github.com/deckhouse/lib-connection/pkg/ssh/gossh/testing"
	"github.com/deckhouse/lib-dhctl/pkg/retry"
	"github.com/stretchr/testify/require"
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

func startContainerAndClientWithContainer(t *testing.T, test *sshtesting.Test, opts ...sshtesting.TestContainerWrapperSettingsOpts) (*Client, *sshtesting.TestContainerWrapper) {
	container := sshtesting.NewTestContainerWrapper(t, test, opts...)
	sess := sshtesting.Session(container)
	keys := container.AgentPrivateKeys()

	sshSettings := sshtesting.CreateDefaultTestSettings(test)
	sshClient := NewClient(context.Background(), sshSettings, sess, keys).WithLoopsParams(ClientLoopsParams{
		NewSession: sshtesting.GetTestLoopParamsForFailed(),
	})

	err := sshClient.Start()
	// expecting no error on client start
	require.NoError(t, err)

	registerStopClient(t, sshClient)

	return sshClient, container
}

func startContainerAndClient(t *testing.T, test *sshtesting.Test, opts ...sshtesting.TestContainerWrapperSettingsOpts) *Client {
	sshClient, _ := startContainerAndClientWithContainer(t, test, opts...)
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

func startContainerAndClientAndKind(t *testing.T, test *sshtesting.Test, opts ...sshtesting.TestContainerWrapperSettingsOpts) (*Client, *sshtesting.TestContainerWrapper) {
	sshClient, container := startContainerAndClientWithContainer(t, test, opts...)

	err := sshtesting.CreateKINDCluster()
	require.NoError(t, err)

	t.Cleanup(func() {
		sshtesting.DeleteKindCluster()
	})

	err = container.Container.DockerNetworkConnect(false, "kind")
	require.NoError(t, err)

	ip, err := sshtesting.GetKINDControlPlaneIP()
	require.NoError(t, err)
	ip = strings.TrimSpace(ip)

	kubeconfig, err := sshtesting.GetKINDKubeconfig()
	require.NoError(t, err)

	re := regexp.MustCompile("127[.]0[.]0[.]1:[0-9]{4,5}")
	newKubeconfig := re.ReplaceAllString(kubeconfig, ip+":6443")

	err = container.Container.CreateDirectory("/config/.kube")
	require.NoError(t, err)

	// TODO revome it. w/o sleep file upload failed
	time.Sleep(30 * time.Second)

	config := test.MustCreateTmpFile(t, newKubeconfig, false, "config")
	file := sshClient.File()
	err = retry.NewLoop("uploading kubeconfig", 20, 3*time.Second).Run(func() error {
		return file.Upload(context.Background(), config, ".kube/config")
	})

	require.NoError(t, err)

	err = container.Container.DownloadKubectl("v1.35.0")
	require.NoError(t, err)

	err = container.Container.CreateDirectory("/etc/kubernetes/")
	require.NoError(t, err)
	err = container.Container.ExecToContainer("symlink of kubeconfig", "ln", "-s", "/config/.kube/config", "/etc/kubernetes/admin.conf")
	require.NoError(t, err)

	return sshClient, container
}
