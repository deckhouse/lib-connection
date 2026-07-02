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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/retry"
	"github.com/stretchr/testify/require"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/clissh"
	"github.com/deckhouse/lib-connection/pkg/ssh/gossh"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
	"github.com/deckhouse/lib-connection/pkg/tests"
)

const expectedFileContent = "Some test data"

func registerStopClient(t *testing.T, sshClient connection.SSHClient) {
	t.Cleanup(func() {
		sshClient.Stop()
	})
}

func newSessionTestLoopParams() gossh.ClientLoopsParams {
	return gossh.ClientLoopsParams{
		NewSession: retry.NewEmptyParams(
			retry.WithWait(2*time.Second),
			retry.WithAttempts(5),
		),
	}
}

func initBothClients(t *testing.T, ctx context.Context, setting settings.Settings, sess *session.Session, keys []session.AgentPrivateKey) (connection.SSHClient, error) {
	goSSHClient := gossh.NewClient(ctx, setting, sess, keys).
		WithLoopsParams(newSessionTestLoopParams())
	err := goSSHClient.Start(ctx)
	if err != nil {
		return nil, err
	}
	registerStopClient(t, goSSHClient)
	cliSSHClient := clissh.NewClient(setting, sess, keys, true)
	err = cliSSHClient.Start(ctx)

	return goSSHClient, err
}

func initContexts(dur time.Duration) (context.Context, context.Context, context.CancelFunc, context.CancelFunc) {
	ctx := context.Background()
	ctx2 := context.Background()
	var emptyDuration time.Duration
	var cancel, cancel2 context.CancelFunc
	if dur != emptyDuration {
		ctx, cancel = context.WithDeadline(ctx, time.Now().Add(dur))
		ctx2, cancel2 = context.WithDeadline(ctx, time.Now().Add(dur))
	}
	return ctx, ctx2, cancel, cancel2
}

func assertFilesOut(t *testing.T, sshClient connection.SSHClient, container *tests.TestContainerWrapper, expectedOutput string, cmd ...string) {
	out, err := container.Container.ExecToContainerWithOut("get content", cmd...)
	require.NoError(t, err, "%v should exec", cmd)
	require.Equal(t, expectedOutput, out, "contents should equality with docker")

	outSSH, _, err := sshClient.Command(cmd[0], cmd[1:]...).Output(context.TODO())
	require.NoError(t, err, "%v should exec via client")
	require.Equal(t, expectedOutput, string(outSSH), "contents should equality with client")
}

// todo mount local directory to container and assert via local exec
func assertFilesViaRemoteRun(t *testing.T, sshClient *gossh.Client, cmd string, expectedOutput string) {
	s, err := sshClient.NewSSHSession()
	require.NoError(t, err, "session should start")
	defer sshClient.UnregisterSession(s)
	out, err := s.Output(cmd)
	require.NoError(t, err)
	// out contains a contant of uploaded file, should be equal to testFile contant
	require.Equal(t, expectedOutput, string(out))
}

func startTargetOnlyForSSH(t *testing.T, test *tests.Test, baseName string) *tests.TestContainerWrapper {
	targetName := baseName + "_target"
	target := tests.NewTestContainerWrapper(
		t,
		test,
		tests.WithContainerName(targetName),
	)

	return target
}

func startTargetWithBastionForSSH(t *testing.T, test *tests.Test, baseName string) (*tests.TestContainerWrapper, *tests.TestContainerWrapper) {
	target := startTargetOnlyForSSH(t, test, baseName)
	bastionName := baseName + "_bastion"
	bastion := tests.NewTestContainerWrapper(
		t,
		test,
		tests.WithContainerName(bastionName),
		tests.WithConnectToContainerNetwork(target),
	)

	return bastion, target
}

func startSSHClient(t *testing.T, test *tests.Test, rt runTest, target *tests.TestContainerWrapper, bastion ...*tests.TestContainerWrapper) connection.SSHClient {
	keys := target.AgentPrivateKeys()
	var sess *session.Session

	if len(bastion) > 0 {
		b := bastion[0]
		sess = tests.SessionWithBastion(target, b)
		keys = append(keys, b.AgentPrivateKeys()...)
	} else {
		sess = tests.Session(target)
	}

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
		registerStopClient(t, sshClient)
	} else {
		sshClient = clissh.NewClient(sshSettings, sess, keys, true)
		prepareScp(t)

		func(t *testing.T) {
			// check connection
			waitClient := gossh.NewClient(ctx, sshSettings, sess, keys).
				WithLoopsParams(newSessionTestLoopParams())
			defer waitClient.Stop()
			err := waitClient.Start(ctx)
			require.NoError(t, err, "sshd should start")
		}(t)
	}

	err := sshClient.Start(ctx)
	// expecting no error on client start
	require.NoError(t, err)

	return sshClient
}

type sshTestClientProvider struct {
	name     string
	provider func(t *testing.T, test *tests.Test, rt runTest) (connection.SSHClient, *tests.TestContainerWrapper)
}

var (
	onlyTargetSSHClientProvider = sshTestClientProvider{
		name: "only target",
		provider: func(t *testing.T, test *tests.Test, rt runTest) (connection.SSHClient, *tests.TestContainerWrapper) {
			baseName := fmt.Sprintf(
				"%s_%s_only_target",
				strings.ToLower(test.FullNameForContainer()),
				strings.ToLower(rt.name),
			)
			container := startTargetOnlyForSSH(t, test, baseName)
			client := startSSHClient(t, test, rt, container)

			return client, container
		},
	}

	viaBastionSSHClientProvider = sshTestClientProvider{
		name: "via bastion",
		provider: func(t *testing.T, test *tests.Test, rt runTest) (connection.SSHClient, *tests.TestContainerWrapper) {
			baseName := fmt.Sprintf(
				"%s_%s_via_bastion",
				strings.ToLower(test.FullNameForContainer()),
				strings.ToLower(rt.name),
			)
			bastion, target := startTargetWithBastionForSSH(t, test, baseName)
			client := startSSHClient(t, test, rt, target, bastion)

			return client, target
		},
	}
)

func startTwoContainersWithClients(t *testing.T, test *tests.Test, createDeckhouseDirs bool) (connection.SSHClient, connection.SSHClient, connection.SSHClient, error) {
	// first container for gossh client
	container := tests.NewTestContainerWrapper(t, test)
	ctx := context.Background()
	sess := tests.Session(container)
	keys := container.AgentPrivateKeys()
	sshSettings := test.Settings()
	goSSHClient := gossh.NewClient(ctx, sshSettings, sess, keys).
		WithLoopsParams(newSessionTestLoopParams())
	err := goSSHClient.Start(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	registerStopClient(t, goSSHClient)

	// second container for clissh
	container2 := tests.NewTestContainerWrapper(t, test, tests.WithConnectToContainerNetwork(container))
	sess2 := tests.Session(container2)
	keys2 := container2.AgentPrivateKeys()

	// check connection
	goSSHClient2 := gossh.NewClient(ctx, sshSettings, sess2, keys2).
		WithLoopsParams(newSessionTestLoopParams())
	err = goSSHClient2.Start(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	goSSHClient2.Stop()

	if createDeckhouseDirs {
		err = container.Container.CreateDeckhouseDirs()
		if err != nil {
			return nil, nil, nil, err
		}
		err = container2.Container.CreateDeckhouseDirs()
		if err != nil {
			return nil, nil, nil, err
		}
	}

	cliSSHClient := clissh.NewClient(sshSettings, sess2, keys2, true)
	err = cliSSHClient.Start(ctx)

	return goSSHClient, cliSSHClient, goSSHClient2, err
}

func prepareScp(t *testing.T) {
	// $PWD/bin is shared between all tests of the run (scp resolves the ssh
	// binary as $PWD/bin/ssh), so never remove it on cleanup: that would break
	// scp for tests still running in parallel and could wipe tools like kind.
	path := filepath.Join(os.Getenv("PWD"), "bin")
	err := os.MkdirAll(path, 0o777)
	require.NoError(t, err)
	err = os.Symlink("/usr/bin/ssh", filepath.Join(path, "ssh"))
	if err != nil && !errors.Is(err, os.ErrExist) {
		require.NoError(t, err)
	}
}

func mustPrepareData(t *testing.T, sshClient connection.SSHClient) {
	err := sshClient.Command("mkdir  -p /tmp/testdata").Run(context.Background())
	require.NoError(t, err)
	err = sshClient.Command(fmt.Sprintf(`echo -n '%s' > /tmp/testdata/first`, expectedFileContent)).Run(context.Background())
	require.NoError(t, err)
	err = sshClient.Command("touch /tmp/testdata/second").Run(context.Background())
	require.NoError(t, err)
	err = sshClient.Command("touch /tmp/testdata/third").Run(context.Background())
	require.NoError(t, err)
	err = sshClient.Command("ln -s /tmp/testdata/first /tmp/link").Run(context.Background())
	require.NoError(t, err)
}

func chmodTmpDir(sshClient connection.SSHClient, nodeTmpPath string) error {
	cmd := sshClient.Command("chmod", "700", nodeTmpPath)
	cmd.Sudo(context.Background())
	return cmd.Run(context.Background())
}
