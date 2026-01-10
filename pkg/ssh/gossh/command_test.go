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
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	sshtesting "github.com/deckhouse/lib-connection/pkg/ssh/gossh/testing"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
)

func TestCommandOutput(t *testing.T) {
	test := sshtesting.ShouldNewTest(t, "TestCommandOutput")

	container := sshtesting.NewTestContainerWrapper(t, test)
	sess := sshtesting.Session(container)
	keys := container.AgentPrivateKeys()

	t.Run("Get command Output", func(t *testing.T) {
		cases := []struct {
			title             string
			command           string
			args              []string
			expectedOutput    string
			expectedErrOutput string
			timeout           time.Duration
			prepareFunc       func(c *SSHCommand) error
			wantErr           bool
			err               string
		}{
			{
				title:          "Just echo, success",
				command:        "echo",
				args:           []string{`"test output"`},
				expectedOutput: "test output\n",
				wantErr:        false,
			},
			{
				title:          "With context",
				command:        `while true; do echo "test"; sleep 5; done`,
				args:           []string{},
				expectedOutput: "test\ntest\n",
				timeout:        7 * time.Second,
				wantErr:        false,
			},
			{
				title:             "Command return error",
				command:           "cat",
				args:              []string{`"/etc/sudoers"`},
				wantErr:           true,
				err:               "Process exited with status 1",
				expectedErrOutput: "cat: /etc/sudoers: Permission denied\n",
			},
			{
				title:   "With opened stdout pipe",
				command: "echo",
				args:    []string{`"test output"`},
				prepareFunc: func(c *SSHCommand) error {
					return c.Run(context.Background())
				},
				wantErr: true,
				err:     "open stdout pipe",
			},
			{
				title:   "With opened stderr pipe",
				command: "echo",
				args:    []string{`"test output"`},
				prepareFunc: func(c *SSHCommand) error {
					buf := new(bytes.Buffer)
					c.session.Stderr = buf
					return nil
				},
				wantErr: true,
				err:     "open stderr pipe",
			},
			{
				title:   "With nil session",
				command: "echo",
				args:    []string{`"test output"`},
				prepareFunc: func(c *SSHCommand) error {
					err := c.session.Close()
					c.session = nil
					return err
				},
				wantErr: true,
				err:     "ssh session not started",
			},
			{
				title:   "With defined buffers",
				command: "echo",
				args:    []string{`"test output"`},
				prepareFunc: func(c *SSHCommand) error {
					c.out = new(bytes.Buffer)
					c.err = new(bytes.Buffer)
					return nil
				},
				expectedOutput: "test output\n",
				wantErr:        false,
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				ctx := context.Background()
				var emptyDuration time.Duration
				var cancel context.CancelFunc
				if c.timeout != emptyDuration {
					ctx, cancel = context.WithDeadline(ctx, time.Now().Add(c.timeout))
				}
				if cancel != nil {
					defer cancel()
				}
				sshSettings := sshtesting.CreateDefaultTestSettings(test)
				sshClient := NewClient(ctx, sshSettings, sess, keys).
					WithLoopsParams(newSessionTestLoopParams())
				err := sshClient.Start()
				// expecting no error on client start
				require.NoError(t, err)

				registerStopClient(t, sshClient)

				cmd := NewSSHCommand(sshClient, c.command, c.args...)

				if c.prepareFunc != nil {
					err = c.prepareFunc(cmd)
					require.NoError(t, err)
				}
				out, errBytes, err := cmd.Output(ctx)
				if !c.wantErr {
					require.NoError(t, err)
					require.Equal(t, c.expectedOutput, string(out))
				} else {
					require.Error(t, err)
					require.Equal(t, c.expectedErrOutput, string(errBytes))
					require.Contains(t, err.Error(), c.err)
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
			prepareFunc       func(c *SSHCommand) error
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
				title:          "With context",
				command:        "while true; do echo \"test\"; sleep 5; done",
				args:           []string{},
				expectedOutput: "test\ntest\n",
				timeout:        7 * time.Second,
				wantErr:        false,
			},
			{
				title:             "Command return error",
				command:           "cat",
				args:              []string{"\"/etc/sudoers\""},
				wantErr:           true,
				err:               "Process exited with status 1",
				expectedErrOutput: "cat: /etc/sudoers: Permission denied\n",
			},
			{
				title:   "With opened stdout pipe",
				command: "echo",
				args:    []string{"\"test output\""},
				prepareFunc: func(c *SSHCommand) error {
					return c.Run(context.Background())
				},
				wantErr: true,
				err:     "open stdout pipe",
			},
			{
				title:   "With opened stderr pipe",
				command: "echo",
				args:    []string{"\"test output\""},
				prepareFunc: func(c *SSHCommand) error {
					buf := new(bytes.Buffer)
					c.session.Stderr = buf
					return nil
				},
				wantErr: true,
				err:     "open stderr pipe",
			},
			{
				title:   "With nil session",
				command: "echo",
				args:    []string{"\"test output\""},
				prepareFunc: func(c *SSHCommand) error {
					err := c.session.Close()
					c.session = nil
					return err
				},
				wantErr: true,
				err:     "ssh session not started",
			},
			{
				title:   "With defined buffers",
				command: "echo",
				args:    []string{"\"test output\""},
				prepareFunc: func(c *SSHCommand) error {
					c.out = new(bytes.Buffer)
					c.err = new(bytes.Buffer)
					return nil
				},
				expectedOutput: "test output\n",
				wantErr:        false,
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				ctx := context.Background()
				var emptyDuration time.Duration
				var cancel context.CancelFunc
				if c.timeout != emptyDuration {
					ctx, cancel = context.WithDeadline(ctx, time.Now().Add(c.timeout))
				}
				if cancel != nil {
					defer cancel()
				}
				sshSettings := sshtesting.CreateDefaultTestSettings(test)
				sshClient := NewClient(ctx, sshSettings, sess, keys).
					WithLoopsParams(newSessionTestLoopParams())
				err := sshClient.Start()
				// expecting no error on client start
				require.NoError(t, err)

				registerStopClient(t, sshClient)

				cmd := NewSSHCommand(sshClient, c.command, c.args...)
				if c.prepareFunc != nil {
					err = c.prepareFunc(cmd)
					require.NoError(t, err)
				}
				combined, err := cmd.CombinedOutput(ctx)
				if !c.wantErr {
					require.NoError(t, err)
					require.Equal(t, c.expectedOutput, string(combined))
				} else {
					require.Error(t, err)
					require.Equal(t, c.expectedErrOutput, string(combined))
					require.Contains(t, err.Error(), c.err)
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
			prepareFunc       func(c *SSHCommand) error
			envs              map[string]string
			wantErr           bool
			err               string
		}{
			{
				title:          "Just echo, success",
				command:        "echo",
				args:           []string{`"est output"`},
				expectedOutput: "test output\n",
				wantErr:        false,
			},
			{
				title:          "Just echo, with envs, success",
				command:        "echo",
				args:           []string{`test output"`},
				expectedOutput: "test output\n",
				envs:           envs,
				wantErr:        false,
			},
			{
				title:          "With context",
				command:        `while true; do echo "test"; sleep 5; done`,
				args:           []string{},
				expectedOutput: "test\ntest\n",
				timeout:        7 * time.Second,
				wantErr:        false,
			},
			{
				title:             "Command return error",
				command:           "cat",
				args:              []string{`"/etc/sudoers"`},
				wantErr:           true,
				err:               "Process exited with status 1",
				expectedErrOutput: "cat: /etc/sudoers: Permission denied\n",
			},
			{
				title:   "With opened stdout pipe",
				command: "echo",
				args:    []string{`"test output\"`},
				prepareFunc: func(c *SSHCommand) error {
					return c.Run(context.Background())
				},
				wantErr: true,
				err:     "ssh: session already started",
			},
			{
				title:   "With nil session",
				command: "echo",
				args:    []string{`"test output"`},
				prepareFunc: func(c *SSHCommand) error {
					err := c.session.Close()
					c.session = nil
					return err
				},
				wantErr: true,
				err:     "ssh session not started",
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				ctx := context.Background()
				var emptyDuration time.Duration
				var cancel context.CancelFunc
				if c.timeout != emptyDuration {
					ctx, cancel = context.WithDeadline(ctx, time.Now().Add(c.timeout))
				}
				if cancel != nil {
					defer cancel()
				}
				sshSettings := sshtesting.CreateDefaultTestSettings(test)
				sshClient := NewClient(ctx, sshSettings, sess, keys).
					WithLoopsParams(newSessionTestLoopParams())
				err := sshClient.Start()
				// expecting no error on client start
				require.NoError(t, err)

				registerStopClient(t, sshClient)

				cmd := NewSSHCommand(sshClient, c.command, c.args...)
				if c.prepareFunc != nil {
					err = c.prepareFunc(cmd)
					require.NoError(t, err)
				}
				if len(c.envs) > 0 {
					cmd.WithEnv(c.envs)
				}

				err = cmd.Run(ctx)
				if !c.wantErr {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
					require.Contains(t, err.Error(), c.err)
				}

				// second run for context after deadline exceeded
				if c.timeout != emptyDuration {
					cmd2 := NewSSHCommand(sshClient, c.command, c.args...)
					if c.prepareFunc != nil {
						err = c.prepareFunc(cmd2)
						require.NoError(t, err)
					}
					if len(c.envs) > 0 {
						cmd2.WithEnv(c.envs)
					}
					err = cmd2.Run(ctx)
					// command should fail to run
					require.Error(t, err)
					require.Contains(t, err.Error(), "context deadline exceeded")

				}
				sshClient.Stop()
			})
		}
	})
}

func TestCommandStart(t *testing.T) {
	test := sshtesting.ShouldNewTest(t, "TestCommandStart")

	container := sshtesting.NewTestContainerWrapper(t, test)
	sess := sshtesting.Session(container)
	keys := container.AgentPrivateKeys()

	ctx := context.Background()
	sshSettings := sshtesting.CreateDefaultTestSettings(test)
	sshClient := NewClient(ctx, sshSettings, sess, keys).
		WithLoopsParams(newSessionTestLoopParams())
	err := sshClient.Start()
	// expecting no error on client start
	require.NoError(t, err)

	registerStopClient(t, sshClient)

	t.Run("Start and stop a command", func(t *testing.T) {
		cases := []struct {
			title             string
			command           string
			args              []string
			expectedOutput    string
			expectedErrOutput string
			timeout           time.Duration
			prepareFunc       func(c *SSHCommand) error
			wantErr           bool
			err               string
		}{
			{
				title:          "Just echo, success",
				command:        "echo",
				args:           []string{`"test output"`},
				expectedOutput: "test output\n",
				wantErr:        false,
			},
			{
				title:          "With context",
				command:        `while true; do echo "test"; sleep 5; done`,
				args:           []string{},
				expectedOutput: "test\ntest\n",
				timeout:        7 * time.Second,
				wantErr:        false,
			},
			{
				title:             "Command return error",
				command:           "cat",
				args:              []string{`"/etc/sudoers"`},
				wantErr:           true,
				err:               "Process exited with status 1",
				expectedErrOutput: "cat: /etc/sudoers: Permission denied\n",
			},
			{
				title:   "With opened stdout pipe",
				command: "echo",
				args:    []string{`"test output"`},
				prepareFunc: func(c *SSHCommand) error {
					return c.Run(context.Background())
				},
				wantErr: true,
				err:     "ssh: session already started",
			},
			{
				title:   "With nil session",
				command: "echo",
				args:    []string{`"test output"`},
				prepareFunc: func(c *SSHCommand) error {
					err := c.session.Close()
					c.session = nil
					return err
				},
				wantErr: true,
				err:     "ssh session not started",
			},
			{
				title:   "waitHandler",
				command: "echo",
				args:    []string{`"test output"`},
				prepareFunc: func(c *SSHCommand) error {
					c.WithWaitHandler(func(err error) {
						if err != nil {
							test.Logger.ErrorF("SSH-agent process exited, now stop. Wait error: %v", err)
							return
						}
						test.Logger.InfoF("SSH-agent process exited, now stop")
					})
					return nil
				},
				expectedOutput: "test output\n",
				wantErr:        false,
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				cmd := NewSSHCommand(sshClient, c.command, c.args...)
				var emptyDuration time.Duration
				if c.timeout != emptyDuration {
					cmd.WithTimeout(c.timeout)
				}
				if c.prepareFunc != nil {
					err = c.prepareFunc(cmd)
					require.NoError(t, err)
				}
				cmd.Cmd(ctx)
				err = cmd.Start()
				if !c.wantErr {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
					require.Contains(t, err.Error(), c.err)
				}
				cmd.Stop()
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
	)

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
			prepareFunc func(c *SSHCommand) error
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
				keys:     make([]session.AgentPrivateKey, 0, 1),
				command:  "echo",
				args:     []string{`"test output"`},
				wantErr:  false,
			},
			{
				title:       "Just echo, failure, with wrong password",
				settings:    sessionWithInvalidPass,
				keys:        keys,
				command:     "echo",
				args:        []string{`"test output"`},
				wantErr:     true,
				err:         "Process exited with status 1",
				errorOutput: "SudoPasswordSorry, try again.\nSudoPasswordSorry, try again.\nSudoPasswordsudo: 3 incorrect password attempts\n",
			},
			{
				title:    "With context",
				settings: sessionWithoutPassword,
				keys:     keys,
				command:  `while true; do echo "test"; sleep 5; done`,
				args:     []string{},
				timeout:  7 * time.Second,
				wantErr:  false,
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				ctx := context.Background()
				var emptyDuration time.Duration
				var cancel context.CancelFunc
				if c.timeout != emptyDuration {
					ctx, cancel = context.WithDeadline(ctx, time.Now().Add(c.timeout))
				}
				if cancel != nil {
					defer cancel()
				}
				sshSettings := sshtesting.CreateDefaultTestSettings(test)
				sshClient := NewClient(ctx, sshSettings, c.settings, c.keys).
					WithLoopsParams(newSessionTestLoopParams())

				err := sshClient.Start()
				// expecting no error on client start
				require.NoError(t, err)

				registerStopClient(t, sshClient)

				cmd := NewSSHCommand(sshClient, c.command, c.args...).CaptureStderr(nil)
				if c.prepareFunc != nil {
					err = c.prepareFunc(cmd)
					require.NoError(t, err)
				}
				cmd.Sudo(ctx)
				err = cmd.Run(ctx)
				if !c.wantErr {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
					require.Contains(t, err.Error(), c.err)
					errBytes := cmd.StderrBytes()

					require.Contains(t, string(errBytes), c.errorOutput)
				}
			})
		}
	})
}
