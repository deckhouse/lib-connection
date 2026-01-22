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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/clissh"
	"github.com/deckhouse/lib-connection/pkg/ssh/gossh"
	sshtesting "github.com/deckhouse/lib-connection/pkg/ssh/gossh/testing"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
	"github.com/deckhouse/lib-dhctl/pkg/retry"
	"github.com/stretchr/testify/require"
)

const expectedFileContent = "Some test data"

func registerStopClient(t *testing.T, sshClient pkg.SSHClient) {
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

func initBothClients(t *testing.T, ctx context.Context, setting settings.Settings, sess *session.Session, keys []session.AgentPrivateKey) (goSshClient pkg.SSHClient, err error) {
	goSshClient = gossh.NewClient(ctx, setting, sess, keys).
		WithLoopsParams(newSessionTestLoopParams())
	err = goSshClient.Start()
	if err != nil {
		return nil, err
	}
	registerStopClient(t, goSshClient)
	var cliSshClient pkg.SSHClient
	cliSshClient = clissh.NewClient(setting, sess, keys, true)
	err = cliSshClient.Start()

	return
}

func initContexts(dur time.Duration) (ctx, ctx2 context.Context, cancel, cancel2 context.CancelFunc) {
	ctx = context.Background()
	ctx2 = context.Background()
	var emptyDuration time.Duration
	if dur != emptyDuration {
		ctx, cancel = context.WithDeadline(ctx, time.Now().Add(dur))
		ctx2, cancel2 = context.WithDeadline(ctx, time.Now().Add(dur))
	}
	return
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

func startTwoContainersWithClients(t *testing.T, test *sshtesting.Test, createDeckhouseDirs bool) (goSshClient, cliSshClient, goSshClient2 pkg.SSHClient, err error) {
	// first container for gossh client
	container := sshtesting.NewTestContainerWrapper(t, test)
	ctx := context.Background()
	sess := sshtesting.Session(container)
	keys := container.AgentPrivateKeys()
	sshSettings := sshtesting.CreateTestSettingNoDebug(test)
	goSshClient = gossh.NewClient(ctx, sshSettings, sess, keys).
		WithLoopsParams(newSessionTestLoopParams())
	err = goSshClient.Start()
	if err != nil {
		return nil, nil, nil, err
	}
	registerStopClient(t, goSshClient)

	// second container for clissh
	container2 := sshtesting.NewTestContainerWrapper(t, test, sshtesting.WithConnectToContainerNetwork(container))
	sess2 := sshtesting.Session(container2)
	keys2 := container2.AgentPrivateKeys()

	// check connection
	goSshClient2 = gossh.NewClient(ctx, sshSettings, sess2, keys2).
		WithLoopsParams(newSessionTestLoopParams())
	err = goSshClient2.Start()
	if err != nil {
		return nil, nil, nil, err
	}
	goSshClient2.Stop()

	if createDeckhouseDirs {
		err = container.Container.CreateDeckhouseDirs()
		if err != nil {
			return
		}
		err = container2.Container.CreateDeckhouseDirs()
		if err != nil {
			return
		}
	}

	cliSshClient = clissh.NewClient(sshSettings, sess2, keys2, true)
	err = cliSshClient.Start()

	return
}

func prepareScp(t *testing.T) {
	path := filepath.Join(os.Getenv("PWD"), "bin")
	err := os.MkdirAll(path, 0o777)
	require.NoError(t, err)
	err = os.Symlink("/usr/bin/ssh", filepath.Join(path, "ssh"))
	require.NoError(t, err)
	t.Cleanup(func() {
		os.RemoveAll(path)
	})
}

func mustPrepareData(t *testing.T, sshClient pkg.SSHClient) {
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

func chmodTmpDir(sshClient pkg.SSHClient, nodeTmpPath string) error {
	cmd := sshClient.Command("chmod", "700", nodeTmpPath)
	cmd.Sudo(context.Background())
	return cmd.Run(context.Background())
}
