package gossh

import (
	"context"
	"fmt"
	"net"
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
	s, err := sshClient.NewSession()
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
