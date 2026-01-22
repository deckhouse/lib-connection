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
	"testing"
	"time"

	"github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/ssh/clissh"
	"github.com/deckhouse/lib-connection/pkg/ssh/gossh"
	sshtesting "github.com/deckhouse/lib-connection/pkg/ssh/gossh/testing"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
	"github.com/stretchr/testify/require"
)

func TestCommandOutput(t *testing.T) {
	test := sshtesting.ShouldNewTest(t, "TestCommandOutput")

	container := sshtesting.NewTestContainerWrapper(t, test)
	sess := sshtesting.Session(container)
	keys := container.AgentPrivateKeys()

	t.Run("Get command Output", func(t *testing.T) {
		cases := []struct {
			title          string
			command        string
			args           []string
			expectedOutput string
			timeout        time.Duration
			wantErr        bool
			err            string
		}{
			{
				title:          "Just echo, success",
				command:        "echo",
				args:           []string{`"test output"`},
				expectedOutput: "test output\n",
				wantErr:        false,
			},
			{
				title:   "With context",
				command: `while true; do echo "test"; sleep 5; done`,
				args:    []string{},
				timeout: 7 * time.Second,
				wantErr: true,
				err:     "context deadline exceeded",
			},
			{
				title:   "Command return error",
				command: "cat",
				args:    []string{`"/etc/sudoers"`},
				wantErr: true,
				err:     "status 1",
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				ctx, ctx2, cancel, cancel2 := initContexts(c.timeout)
				if cancel != nil && cancel2 != nil {
					defer cancel()
					defer cancel2()
				}
				sshSettings := sshtesting.CreateDefaultTestSettings(test)
				goSshClient, err := initBothClients(t, ctx, sshSettings, sess, keys)
				require.NoError(t, err)

				var gocmd, clicmd pkg.Command
				gocmd = gossh.NewSSHCommand(goSshClient.(*gossh.Client), c.command, c.args...)
				clicmd = clissh.NewCommand(sshSettings, sess, c.command, c.args...)

				goout, _, err := gocmd.Output(ctx)
				cliout, _, err2 := clicmd.Output(ctx2)
				if !c.wantErr {
					require.NoError(t, err)
					require.NoError(t, err2)
					require.Equal(t, c.expectedOutput, string(goout))
					require.Equal(t, c.expectedOutput, string(cliout))
				} else {
					require.Error(t, err)
					require.Contains(t, err.Error(), c.err)
					require.Error(t, err2)
					require.Contains(t, err2.Error(), c.err)
				}
			})
		}
	})
}

func TestCommandCombinedOutput(t *testing.T) {
	test := sshtesting.ShouldNewTest(t, "TestCommandCombinedOutput")

	container := sshtesting.NewTestContainerWrapper(t, test)
	sess := sshtesting.Session(container)
	keys := container.AgentPrivateKeys()

	t.Run("Get command CombinedOutput", func(t *testing.T) {
		cases := []struct {
			title             string
			command           string
			args              []string
			expectedOutput    string
			expectedErrOutput string
			timeout           time.Duration
			wantErr           bool
			err               string
		}{
			{
				title:          "Just echo, success",
				command:        "echo",
				args:           []string{"\"test output\""},
				expectedOutput: "test output\n",
				wantErr:        false,
			},
			{
				title:   "With context",
				command: "while true; do echo \"test\"; sleep 5; done",
				args:    []string{},
				timeout: 7 * time.Second,
				wantErr: true,
				err:     "context deadline exceeded",
			},
			{
				title:             "Command return error",
				command:           "cat",
				args:              []string{"\"/etc/sudoers\""},
				wantErr:           true,
				err:               "status 1",
				expectedErrOutput: "cat: /etc/sudoers: Permission denied\n",
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				ctx, ctx2, cancel, cancel2 := initContexts(c.timeout)
				if cancel != nil && cancel2 != nil {
					defer cancel()
					defer cancel2()
				}
				sshSettings := sshtesting.CreateTestSettingNoDebug(test)
				goSshClient, err := initBothClients(t, ctx, sshSettings, sess, keys)
				require.NoError(t, err)

				var gocmd, clicmd pkg.Command
				gocmd = gossh.NewSSHCommand(goSshClient.(*gossh.Client), c.command, c.args...)
				clicmd = clissh.NewCommand(sshSettings, sess, c.command, c.args...)
				gocombined, err := gocmd.CombinedOutput(ctx)
				clicombined, err2 := clicmd.CombinedOutput(ctx2)
				if !c.wantErr {
					require.NoError(t, err)
					require.NoError(t, err2)
					require.Contains(t, string(gocombined), c.expectedOutput)
					require.Contains(t, string(clicombined), c.expectedOutput)
				} else {
					require.Error(t, err)
					require.Contains(t, string(gocombined), c.expectedErrOutput)
					require.Contains(t, string(clicombined), c.expectedErrOutput)
					require.Contains(t, err.Error(), c.err)
					require.Error(t, err2)
					require.Contains(t, err2.Error(), c.err)
				}
			})
		}
	})
}

func TestCommandRun(t *testing.T) {
	test := sshtesting.ShouldNewTest(t, "TestCommandRun")

	container := sshtesting.NewTestContainerWrapper(t, test)
	sess := sshtesting.Session(container)
	keys := container.AgentPrivateKeys()

	// evns test
	envs := make(map[string]string)
	envs["TEST_ENV"] = "test"

	t.Run("Run a command", func(t *testing.T) {
		cases := []struct {
			title             string
			command           string
			args              []string
			expectedOutput    string
			expectedErrOutput string
			timeout           time.Duration
			prepareFunc       func(c pkg.Command) error
			envs              map[string]string
			wantErr           bool
			err               string
		}{
			{
				title:          "Just echo, success",
				command:        "echo",
				args:           []string{"\"test output\""},
				expectedOutput: "test output\n",
				wantErr:        false,
			},
			{
				title:          "Just echo, with envs, success",
				command:        "echo",
				args:           []string{"\"test output\""},
				expectedOutput: "test output\n",
				envs:           envs,
				wantErr:        false,
			},
			{
				title:             "With context",
				command:           "while true; do echo \"test\"; sleep 5; done",
				args:              []string{},
				timeout:           7 * time.Second,
				wantErr:           true,
				err:               "context deadline exceeded",
				expectedErrOutput: "test\ntest\n",
			},
			{
				title:             "Command return error",
				command:           "cat",
				args:              []string{`"/etc/sudoers"`},
				wantErr:           true,
				err:               "status 1",
				expectedErrOutput: "cat: /etc/sudoers: Permission denied\n",
			},
			{
				title:   "With opened stdout pipe",
				command: "echo",
				args:    []string{"\"test output\""},
				prepareFunc: func(c pkg.Command) error {
					return c.Run(context.Background())
				},
				wantErr: true,
				err:     "already started",
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				var emptyDuration time.Duration
				ctx, ctx2, cancel, cancel2 := initContexts(c.timeout)
				if cancel != nil && cancel2 != nil {
					defer cancel()
					defer cancel2()
				}
				sshSettings := sshtesting.CreateDefaultTestSettings(test)
				goSshClient, err := initBothClients(t, ctx, sshSettings, sess, keys)
				require.NoError(t, err)

				var gocmd, clicmd pkg.Command
				gocmd = gossh.NewSSHCommand(goSshClient.(*gossh.Client), c.command, c.args...)
				clicmd = clissh.NewCommand(sshSettings, sess, c.command, c.args...)
				clicmd.Cmd(ctx2)
				if c.prepareFunc != nil {
					err = c.prepareFunc(gocmd)
					require.NoError(t, err)
					err = c.prepareFunc(clicmd)
					require.NoError(t, err)
				}
				if len(c.envs) > 0 {
					gocmd.WithEnv(c.envs)
					clicmd.WithEnv(c.envs)
				}

				err = gocmd.Run(ctx)
				err2 := clicmd.Run(ctx2)
				if !c.wantErr {
					require.NoError(t, err)
					require.NoError(t, err2)
				} else {
					require.Error(t, err)
					require.Contains(t, err.Error(), c.err)
					require.Error(t, err2)
					require.Contains(t, err2.Error(), c.err)
				}

				// second run for context after deadline exceeded
				if c.timeout != emptyDuration {
					gocmd2 := gossh.NewSSHCommand(goSshClient.(*gossh.Client), c.command, c.args...)
					clicmd2 := clissh.NewCommand(sshSettings, sess, c.command, c.args...)
					clicmd2.Cmd(ctx2)
					if c.prepareFunc != nil {
						err = c.prepareFunc(gocmd2)
						require.NoError(t, err)
						err = c.prepareFunc(clicmd2)
						require.NoError(t, err)
					}
					if len(c.envs) > 0 {
						gocmd2.WithEnv(c.envs)
						clicmd2.WithEnv(c.envs)
					}
					err = gocmd2.Run(ctx)
					err2 = clicmd2.Run(ctx2)
					// command should fail to run
					require.Error(t, err)
					require.Contains(t, err.Error(), "context deadline exceeded")
					require.Error(t, err2)
					require.Contains(t, err2.Error(), "context deadline exceeded")

				}
			})
		}
	})
}

func TestCommandSudoRun(t *testing.T) {
	test := sshtesting.ShouldNewTest(t, "TestCommandRunSudo")

	container := sshtesting.NewTestContainerWrapper(t, test, sshtesting.WithNoPassword())
	keys := container.AgentPrivateKeys()

	// starting openssh container with password auth
	containerWithPass := sshtesting.NewTestContainerWrapper(
		t,
		test,
		sshtesting.WithPassword(sshtesting.RandPassword(12)),
		sshtesting.WithConnectToContainerNetwork(container),
	)
	keysContainerWithPass := containerWithPass.AgentPrivateKeys()

	sessionWithoutPassword := sshtesting.Session(container)

	sessionWithValidPass := sshtesting.Session(containerWithPass)

	// client with wrong sudo password
	sessionWithInvalidPass := sshtesting.Session(containerWithPass, func(input *session.Input) {
		input.BecomePass = sshtesting.RandPassword(3)
	})

	t.Run("Run a command with sudo", func(t *testing.T) {
		cases := []struct {
			title       string
			settings    *session.Session
			keys        []session.AgentPrivateKey
			command     string
			args        []string
			timeout     time.Duration
			wantErr     bool
			err         string
			errorOutput string
		}{
			{
				title:    "Just echo, success",
				settings: sessionWithoutPassword,
				keys:     keys,
				command:  "echo",
				args:     []string{`"test output"`},
				wantErr:  false,
			},
			{
				title:    "Just echo, success, with password",
				settings: sessionWithValidPass,
				keys:     keysContainerWithPass,
				command:  "echo",
				args:     []string{`"test output"`},
				wantErr:  false,
			},
			{
				title:       "Just echo, failure, with wrong password",
				settings:    sessionWithInvalidPass,
				keys:        keysContainerWithPass,
				command:     "echo",
				args:        []string{`"test output"`},
				wantErr:     true,
				err:         "status 1",
				errorOutput: "SudoPasswordSorry, try again.\nSudoPasswordSorry, try again.\nSudoPasswordsudo: 3 incorrect password attempts\n",
			},
			{
				title:    "With context",
				settings: sessionWithoutPassword,
				keys:     keys,
				command:  `while true; do echo "test"; sleep 5; done`,
				args:     []string{},
				timeout:  7 * time.Second,
				wantErr:  true,
				err:      "context deadline exceeded",
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				ctx, ctx2, cancel, cancel2 := initContexts(c.timeout)
				if cancel != nil && cancel2 != nil {
					defer cancel()
					defer cancel2()
				}
				sshSettings := sshtesting.CreateDefaultTestSettings(test)
				goSshClient, err := initBothClients(t, ctx, sshSettings, c.settings, c.keys)
				require.NoError(t, err)

				var gocmd, clicmd pkg.Command
				gocmd = gossh.NewSSHCommand(goSshClient.(*gossh.Client), c.command, c.args...)
				clicmd = clissh.NewCommand(sshSettings, c.settings, c.command, c.args...)
				clicmd.Cmd(ctx2)

				gocmd.Sudo(ctx)
				clicmd.Sudo(ctx)
				err = gocmd.Run(ctx)
				err2 := clicmd.Run(ctx2)
				if !c.wantErr {
					require.NoError(t, err)
					require.NoError(t, err2)
				} else {
					require.Error(t, err)
					require.Contains(t, err.Error(), c.err)
					errBytes := gocmd.StderrBytes()
					require.Contains(t, string(errBytes), c.errorOutput)

					require.Error(t, err2)
					require.Contains(t, err2.Error(), c.err)
				}
			})
		}
	})
}
