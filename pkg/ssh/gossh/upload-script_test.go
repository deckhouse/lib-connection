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
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/retry"
	"github.com/stretchr/testify/require"

	"github.com/deckhouse/lib-connection/pkg/tests"
)

func TestUploadScriptExecute(t *testing.T) {
	test := tests.ShouldNewTest(t, "TestUploadScriptExecute")

	sshClient, container := startContainerAndClientWithContainer(t, test, tests.WithNoWriteSSHDConfig())
	sshClient.WithLoopsParams(ClientLoopsParams{
		NewSession: retry.NewEmptyParams(
			retry.WithAttempts(5),
			retry.WithWait(250*time.Millisecond),
		),
	})

	// we don't have /opt/deckhouse in the container, so we should create it before start any UploadScript with sudo
	err := container.Container.CreateDeckhouseDirs()
	require.NoError(t, err, "could not create deckhouse dirs")

	script := `#!/bin/bash
if [[ $# -eq 0 ]]; then
  echo "Error: No arguments provided."
  exit 1
elif [[ $# -gt 1 ]]; then
  echo "Usage: $0 <arg1>"
  exit 1
else
  echo "provided: $1"
fi
`
	scriptFile := test.MustCreateTmpFile(t, script, true, "execute_script", "script.sh")

	// evns test
	envs := map[string]string{
		"TEST_ENV": "test",
	}

	t.Run("Upload and execute script to container via existing ssh client", func(t *testing.T) {
		cases := []struct {
			title      string
			scriptPath string
			scriptArgs []string
			expected   string
			wantSudo   bool
			envs       map[string]string
			wantErr    bool
			err        string
		}{
			{
				title:      "Happy case",
				scriptPath: scriptFile,
				scriptArgs: []string{"one"},
				expected:   "provided: one\n",
				wantSudo:   false,
				wantErr:    false,
			},
			{
				title:      "Happy case with sudo",
				scriptPath: scriptFile,
				scriptArgs: []string{"one"},
				expected:   "SUDO-SUCCESS\nprovided: one\n",
				wantSudo:   true,
				wantErr:    false,
			},
			{
				title:      "Error by remote script execution",
				scriptPath: scriptFile,
				scriptArgs: []string{"one", "two"},
				wantSudo:   false,
				wantErr:    true,
				err:        "execute on remote",
			},
			{
				title:      "With envs",
				scriptPath: scriptFile,
				scriptArgs: []string{"one"},
				expected:   "provided: one\n",
				wantSudo:   false,
				envs:       envs,
				wantErr:    false,
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				test.RunSubTestParallel(t)

				s := sshClient.UploadScript(c.scriptPath, c.scriptArgs...)
				s.WithCleanupAfterExec(true)

				if c.wantSudo {
					s.Sudo()
				}
				if len(c.envs) > 0 {
					s.WithEnvs(c.envs)
				}

				out, err := s.Execute(context.Background())
				if c.wantErr {
					require.Error(t, err)
					require.Contains(t, err.Error(), c.err)
					return
				}

				require.NoError(t, err)
				require.Equal(t, c.expected, string(out))
			})
		}
	})
}

func TestUploadScriptExecuteBundle(t *testing.T) {
	test := tests.ShouldNewTest(t, "TestUploadScriptExecuteBundle")

	sshClient, container := startContainerAndClientWithContainer(t, test, tests.WithNoWriteSSHDConfig())
	sshClient.WithLoopsParams(ClientLoopsParams{
		NewSession: retry.NewEmptyParams(
			retry.WithAttempts(5),
			retry.WithWait(250*time.Millisecond),
		),
	})

	// we don't have /opt/deckhouse in the container, so we should create it before start any UploadScript with sudo
	err := container.Container.CreateDeckhouseDirs()
	require.NoError(t, err, "could not create deckhouse dirs")

	const entrypoint = "test.sh"

	testDir := tests.PrepareFakeBashibleBundle(t, test, entrypoint, "bashible")

	t.Run("Upload and execute bundle to container via existing ssh client", func(t *testing.T) {
		cases := []struct {
			title       string
			scriptArgs  []string
			parentDir   string
			bundleDir   string
			prepareFunc func() error
			wantErr     bool
			err         string
		}{
			{
				title:      "Happy case",
				scriptArgs: []string{},
				parentDir:  testDir,
				bundleDir:  "bashible",
				wantErr:    false,
			},
			{
				title:      "Bundle error",
				scriptArgs: []string{"--add-failure"},
				parentDir:  testDir,
				bundleDir:  "bashible",
				wantErr:    true,
			},
			{
				title:      "Wrong bundle directory",
				scriptArgs: []string{},
				parentDir:  "/path/to/nonexistent/dir",
				bundleDir:  "wrong_bundle",
				wantErr:    true,
				err:        "tar bundle: failed to walk path",
			},
			{
				title:      "Upload error",
				scriptArgs: []string{""},
				parentDir:  testDir,
				bundleDir:  "bashible",
				prepareFunc: func() error {
					cmd := sshClient.Command("chmod", "700", container.Container.ContainerSettings().NodeTmpPath)
					cmd.Sudo(context.Background())
					return cmd.Run(context.Background())
				},
				wantErr: true,
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				s := sshClient.UploadScript(entrypoint, c.scriptArgs...)
				if c.prepareFunc != nil {
					err = c.prepareFunc()
					require.NoError(t, err)
				}

				_, err := s.ExecuteBundle(context.Background(), c.parentDir, c.bundleDir)
				if c.wantErr {
					require.Error(t, err)
					require.Contains(t, err.Error(), c.err)
					return
				}

				require.NoError(t, err)
			})
		}
	})
}
