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

	"github.com/stretchr/testify/require"

	sshtesting "github.com/deckhouse/lib-connection/pkg/ssh/gossh/testing"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
)

func TestOnlyPreparePrivateKeys(t *testing.T) {
	test := sshtesting.ShouldNewTest(t, "TestOnlyPreparePrivateKeys")

	// genetaring ssh keys
	keyWithoutPath, _, err := sshtesting.GenerateKeys(test, "")
	require.NoError(t, err, "failed to generate keys without password")

	wrongKeyPath := test.MustCreateTmpFile(t, "Hello world", false, sshtesting.PrivateKeysRoot, "wrong-key")

	validPassword := sshtesting.RandPassword(12)
	keyWithPass, _, err := sshtesting.GenerateKeys(test, validPassword)
	require.NoError(t, err, "failed to generate keys with password")

	t.Run("OnlyPrepareKeys cases", func(t *testing.T) {
		type testCase struct {
			title   string
			keys    []session.AgentPrivateKey
			wantErr bool
			err     string
		}

		cases := []testCase{
			{
				title:   "No keys",
				keys:    make([]session.AgentPrivateKey, 0, 1),
				wantErr: false,
			},
			{
				title:   "Key auth, no password",
				keys:    []session.AgentPrivateKey{{Key: keyWithoutPath}},
				wantErr: false,
			},
			{
				title:   "Key auth, no password, noexistent key",
				keys:    []session.AgentPrivateKey{{Key: "/tmp/noexistent-key"}},
				wantErr: true,
				err:     "open /tmp/noexistent-key: no such file or directory",
			},
			{
				title:   "Key auth, no password, wrong key",
				keys:    []session.AgentPrivateKey{{Key: wrongKeyPath}},
				wantErr: true,
				err:     "ssh: no key found",
			},
			{
				title:   "Key auth, with passphrase",
				keys:    []session.AgentPrivateKey{{Key: keyWithPass, Passphrase: validPassword}},
				wantErr: false,
			},
			{
				title:   "Key auth, with wrong passphrase",
				keys:    []session.AgentPrivateKey{{Key: keyWithPass, Passphrase: sshtesting.RandPassword(6)}},
				wantErr: true,
				err:     "x509: decryption password incorrect",
			},
		}

		assertError := func(t *testing.T, tst testCase, err error) {
			if !tst.wantErr {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tst.err)
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				sshSettings := sshtesting.CreateDefaultTestSettings(test)
				sshClient := NewClient(context.Background(), sshSettings, nil, c.keys)
				err := sshClient.OnlyPreparePrivateKeys()
				assertError(t, c, err)

				// double run
				err = sshClient.OnlyPreparePrivateKeys()
				assertError(t, c, err)
			})
		}

	})
}

func TestClientStart(t *testing.T) {
	test := sshtesting.ShouldNewTest(t, "TestClientStart")

	const bastionUserName = "bastionuser"

	container := sshtesting.NewTestContainerWrapper(t, test)
	bastion := sshtesting.NewTestContainerWrapper(
		t,
		test,
		sshtesting.WithConnectToContainerNetwork(container),
		sshtesting.WithWriteSSHDConfig(),
		sshtesting.WithUserName(bastionUserName),
		sshtesting.WithAuthSettings(container),
	)

	agent := sshtesting.StartTestAgent(t, container)

	t.Run("Start ssh client", func(t *testing.T) {
		type testCase struct {
			title      string
			settings   *session.Session
			keys       []session.AgentPrivateKey
			wantErr    bool
			err        string
			authSock   string
			loopParams ClientLoopsParams
		}

		keys := []session.AgentPrivateKey{{Key: container.PublicKeyPath()}}
		noKeys := make([]session.AgentPrivateKey, 0, 1)
		overrideIncorrectPort := sshtesting.OverrideSessionWithIncorrectPort(container, bastion)

		cases := []testCase{
			{
				title:    "Password auth, no keys",
				settings: sshtesting.Session(container),
				keys:     make([]session.AgentPrivateKey, 0, 1),
				wantErr:  false,
			},
			{
				title:    "Key auth, no password",
				settings: sshtesting.Session(container),
				keys:     keys,
				wantErr:  false,
			},
			{
				title:    "SSH_AUTH_SOCK auth",
				settings: sshtesting.Session(container),
				keys:     keys,
				wantErr:  false,
				authSock: agent.SockPath(),
			},
			{
				title:    "SSH_AUTH_SOCK auth, wrong socket",
				settings: sshtesting.Session(container),
				keys:     noKeys,
				wantErr:  true,
				err:      "Failed to open SSH_AUTH_SOCK",
				authSock: "/run/nonexistent",
			},
			{
				title:    "Key auth, no password, wrong key",
				settings: sshtesting.Session(container),
				keys:     []session.AgentPrivateKey{{Key: "/tmp/noexistent-key"}},
				wantErr:  true,
			},
			{
				title:    "No session",
				settings: nil,
				keys:     []session.AgentPrivateKey{{Key: "/tmp/noexistent-key"}},
				wantErr:  true,
				err:      "possible bug in ssh client: session should be created before start",
			},
			{
				title:    "No auth",
				settings: sshtesting.Session(container),
				keys:     noKeys,
				wantErr:  true,
				err:      "one of SSH keys, SSH_AUTH_SOCK environment variable or become password should be not empty",
				authSock: "",
			},
			{
				title:    "Wrong port",
				settings: sshtesting.Session(container, overrideIncorrectPort),
				keys:     keys,
				wantErr:  true,
				err:      "Failed to connect to master host",
				authSock: "",
				loopParams: ClientLoopsParams{
					ConnectToHostDirectly: sshtesting.GetTestLoopParamsForFailed(),
				},
			},
			{
				title:    "With bastion, key auth",
				settings: sshtesting.SessionWithBastion(container, bastion),
				keys:     keys,
				wantErr:  false,
				authSock: "",
			},
			{
				title:    "With bastion, password auth",
				settings: sshtesting.SessionWithBastion(container, bastion),
				keys:     noKeys,
				wantErr:  false,
				authSock: "",
			},
			{
				title:    "With bastion, no auth",
				settings: sshtesting.SessionWithBastion(container, bastion),
				keys:     noKeys,
				wantErr:  true,
				err:      "No credentials present to connect to bastion host",
				authSock: "",
			},
			{
				title:    "With bastion, SSH_AUTH_SOCK auth",
				settings: sshtesting.SessionWithBastion(container, bastion),
				keys:     keys,
				wantErr:  false,
				authSock: agent.SockPath(),
			},
			{
				title: "With bastion, key auth, wrong target host",
				settings: sshtesting.SessionWithBastion(container, bastion, func(input *session.Input) {
					input.AvailableHosts = []session.Host{{Host: container.ContainerIP(), Name: container.ContainerIP()}}
				}),
				keys:     keys,
				wantErr:  true,
				err:      "Failed to connect to target host through bastion host",
				authSock: "",
				loopParams: ClientLoopsParams{
					ConnectToHostViaBastion: sshtesting.GetTestLoopParamsForFailed(),
				},
			},
			{
				title:    "With bastion, key auth, wrong bastion port",
				settings: sshtesting.SessionWithBastion(container, bastion, overrideIncorrectPort),
				keys:     keys,
				wantErr:  true,
				err:      "Could not connect to bastion host",
				authSock: "",
				loopParams: ClientLoopsParams{
					ConnectToBastion: sshtesting.GetTestLoopParamsForFailed(),
				},
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				sshSettings := sshtesting.CreateDefaultTestSettingsWithAgent(test, c.authSock)

				sshClient := NewClient(context.Background(), sshSettings, c.settings, c.keys).
					WithLoopsParams(c.loopParams)

				err := sshClient.Start()
				sshClient.Stop()

				if !c.wantErr {
					require.NoError(t, err)
					test.Logger.InfoLn("client started successfully")
					return
				}

				require.Error(t, err)
				require.Contains(t, err.Error(), c.err)
			})
		}

	})
}

func TestClientKeepalive(t *testing.T) {
	sshtesting.CheckSkipSSHTest(t, "TestClientKeepalive")

	t.Run("keepalive test", func(t *testing.T) {
		test := sshtesting.ShouldNewTest(t, "TestClientKeepalive")

		container := sshtesting.NewTestContainerWrapper(t, test)
		sess := sshtesting.Session(container)
		keys := container.AgentPrivateKeys()

		sshSettings := sshtesting.CreateDefaultTestSettings(test)
		sshClient := NewClient(context.Background(), sshSettings, sess, keys).
			WithLoopsParams(ClientLoopsParams{
				NewSession: sshtesting.GetTestLoopParamsForFailed(),
			})

		err := sshClient.Start()
		// expecting no error on client start
		require.NoError(t, err, "failed to start ssh client")
		// test case: stopping container for a while, waiting for client recreation, creating new session, expecting no error
		time.Sleep(2 * time.Second)

		registerStopClient(t, sshClient)

		runEcho := func(t *testing.T, msg string) {
			s, err := sshClient.NewSession()
			require.NoError(t, err)

			cmd := fmt.Sprintf(`echo -n "%s"`, msg)

			out, err := s.CombinedOutput(cmd)
			require.NoError(t, err, "failed to run command '%s'", cmd)
			require.Contains(t, string(out), msg, "run command '%s' should contains output '%s'. Out: %s", cmd, msg, out)
		}

		runEcho(t, "Hello before restart")

		err = container.Container.Restart(true, 2*time.Second)
		require.NoError(t, err, "failed to restart container")

		runEcho(t, "Hello after restart")
	})

	t.Run("keepalive with context test", func(t *testing.T) {
		test := sshtesting.ShouldNewTest(t, "TestClientKeepaliveContext")

		container := sshtesting.NewTestContainerWrapper(t, test)
		sess := sshtesting.Session(container)
		keys := container.AgentPrivateKeys()

		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(5*time.Second))
		defer cancel()
		sshSettings := sshtesting.CreateDefaultTestSettings(test)
		sshClient := NewClient(ctx, sshSettings, sess, keys)
		err := sshClient.Start()
		// expecting no error on client start
		require.NoError(t, err)

		registerStopClient(t, sshClient)

		time.Sleep(10 * time.Second)
		// expecting client is not live
		sshClient.Stop()
		err = sshClient.Start()
		require.Error(t, err)
		require.Contains(t, err.Error(), "deadline exceeded")
	})

	t.Run("client start with context test", func(t *testing.T) {
		test := sshtesting.ShouldNewTest(t, "TestClientKeepaliveContextStartClient")

		container := sshtesting.NewTestContainerWrapper(t, test)
		sess := sshtesting.Session(container, sshtesting.OverrideSessionWithIncorrectPort(container))
		keys := container.AgentPrivateKeys()

		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(20*time.Second))
		defer cancel()
		sshSettings := sshtesting.CreateDefaultTestSettings(test)
		sshClient := NewClient(ctx, sshSettings, sess, keys)
		err := sshClient.Start()
		// expecting error on client start: host is unreachable, but loop should exit on context deadline exceeded
		require.Error(t, err)
		require.Contains(t, err.Error(), "Loop was canceled: context deadline exceeded")
		// expecting client is not live
		sshClient.Stop()
		err = sshClient.Start()
		require.Error(t, err)
		require.Contains(t, err.Error(), "deadline exceeded")
	})
}

func TestDialContextVerySmall(t *testing.T) {
	test := sshtesting.ShouldNewTest(t, "TestDialContextVerySmall")

	sess := sshtesting.FakeSession()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(10*time.Millisecond))
	defer cancel()
	sshSettings := sshtesting.CreateDefaultTestSettings(test)
	sshClient := NewClient(ctx, sshSettings, sess, make([]session.AgentPrivateKey, 0, 1))
	err := sshClient.Start()
	// expecting error on client start: host is unreachable, but loop should exit on context deadline exceeded
	require.Error(t, err)
	require.Contains(t, err.Error(), "Loop was canceled: context deadline exceeded")
	// expecting client is not live
	sshClient.Stop()
	err = sshClient.Start()
	require.Error(t, err)
	require.Contains(t, err.Error(), "deadline exceeded")
}
