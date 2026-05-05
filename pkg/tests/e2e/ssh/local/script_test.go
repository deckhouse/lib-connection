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

package local_test

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/deckhouse/lib-connection/pkg/ssh/local"
	"github.com/deckhouse/lib-connection/pkg/tests"
)

const testRunScript = `#! /bin/bash
echo -n $@
exit 0`

func TestScriptExecute(t *testing.T) {
	tst := tests.ShouldNewIntegrationTest(t, "LocalExecuteScript")

	path, err := tst.CreateTmpFile(testRunScript, true, "run-local")
	require.NoError(t, err, "Script for local run should created")

	script := local.NewNodeInterface(tst.Settings()).UploadScript(path, "arg 1", "arg 2")

	stdout, err := script.Execute(context.Background())
	require.NoError(t, err, "local script should executed")
	require.Equal(t, "arg 1 arg 2", string(stdout))
}

func TestExecuteBundle(t *testing.T) {
	loggerBuf := bytes.NewBuffer(nil)

	tst := tests.ShouldNewIntegrationTest(
		t,
		"TestUploadScriptExecuteBundle",
		tests.TestWithLoggerBuffer(loggerBuf),
		tests.TestWithPrettyLogger(true),
		tests.TestNoLogDebug(true),
	)

	nodeTmpDir := tst.MustMkSubDirs(t, "node-tmp")
	tst.WithNodeTmpDir(nodeTmpDir)

	entrypoint := "test.sh"

	testDir := tests.PrepareFakeBashibleBundle(t, tst, entrypoint, "bashible")

	node := local.NewNodeInterface(tst.Settings())

	t.Run("Upload and execute bundle local", func(t *testing.T) {
		cases := []struct {
			title           string
			scriptArgs      []string
			parentDir       string
			bundleDir       string
			wantErr         bool
			err             string
			loggerOutAssert func(t *testing.T, buf *bytes.Buffer)
		}{
			{
				title:           "Happy case",
				scriptArgs:      []string{},
				parentDir:       testDir,
				bundleDir:       "bashible",
				wantErr:         false,
				loggerOutAssert: tests.AssertLogBufferNoErrorBundle,
			},

			{
				title:           "Bundle with info out",
				scriptArgs:      []string{"--info-out"},
				parentDir:       testDir,
				bundleDir:       "bashible",
				wantErr:         false,
				loggerOutAssert: tests.AssertLogBufferBundleWithInfo,
			},

			{
				title:           "Bundle error",
				scriptArgs:      []string{"--add-failure"},
				parentDir:       testDir,
				bundleDir:       "bashible",
				wantErr:         true,
				loggerOutAssert: tests.AssertLogBufferWithErrorBundle,
			},
			{
				title:      "Wrong bundle directory",
				scriptArgs: []string{},
				parentDir:  "/tmp/to/nonexistent/diraqqswd",
				bundleDir:  "wrong_bundle",
				wantErr:    true,
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				randDir := tests.RandString(6)
				bundleDest := tst.MustMkSubDirs(t, randDir)

				bootstrapDir := filepath.Join(bundleDest, "bashible")

				c.scriptArgs = append(c.scriptArgs, "--bootstrap-dir", bootstrapDir)

				s := node.UploadScript(entrypoint, c.scriptArgs...)

				sImpl, ok := s.(*local.Script)
				require.True(t, ok, "should convert to impl")

				sImpl.WithBundleDest(bundleDest).WithForceNoSudoForBundle(true)

				loggerBuf.Reset()

				_, err := s.ExecuteBundle(context.Background(), c.parentDir, c.bundleDir)

				if c.loggerOutAssert != nil {
					c.loggerOutAssert(t, loggerBuf)
				}

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
