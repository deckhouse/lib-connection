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
	"context"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/deckhouse/lib-connection/pkg/ssh/local"
	"github.com/deckhouse/lib-connection/pkg/tests"
)

func TestCommandOutput(t *testing.T) {
	tst := tests.ShouldNewIntegrationTest(
		t,
		"LocalOutputCommand",
		tests.TestWithParallelRun(true),
	)

	content := "Hello world"

	path := tst.MustCreateTmpFile(t, content, false, "test_out.txt")

	cmd := local.NewCommand(tst.Settings(), "cat", path)
	stdout, _, err := cmd.Output(context.Background())
	require.NoError(t, err, "should exec")
	require.Equal(t, content, string(stdout), "content should equal")
}

func TestCommandCombinedOutput(t *testing.T) {
	tst := tests.ShouldNewIntegrationTest(
		t,
		"LocalCombineOutput",
		tests.TestWithParallelRun(true),
	)

	scriptPath := stdoutStdErrScript(t, tst)

	cmd := local.NewCommand(tst.Settings(), scriptPath)
	stdout, err := cmd.CombinedOutput(context.Background())

	require.NoError(t, err, "combine out should run")
	require.Equal(t, "Stdout\nStderr\n", string(stdout))
}

func TestCommandRun(t *testing.T) {
	tst := tests.ShouldNewIntegrationTest(
		t,
		"LocalRun",
		tests.TestWithParallelRun(true),
	)

	scriptPath := stdoutStdErrScript(t, tst)

	cmd := local.NewCommand(tst.Settings(), scriptPath)

	stdout := ""
	stderr := ""

	cmd.WithStdoutHandler(func(line string) {
		stdout = fmt.Sprintf("%s%s", stdout, line)
	})

	cmd.WithStderrHandler(func(line string) {
		stderr = fmt.Sprintf("%s%s", stderr, line)
	})

	err := cmd.Run(context.Background())

	require.NoError(t, err, "run should success")
	require.Equal(t, "Stdout", stdout, "stdout from handler")
	require.Equal(t, "Stdout", string(cmd.StdoutBytes()), "stdout from cmd")

	require.Equal(t, "Stderr", stderr, "stderr from handler")
	require.Equal(t, "Stderr", string(cmd.StderrBytes()), "stderr from cmd")
}

func TestCommandRetryOnTextFileBusy(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ETXTBSY is not enforced on this OS")
	}

	tst := tests.ShouldNewIntegrationTest(
		t,
		"LocalTextFileBusy",
		tests.TestWithParallelRun(true),
	)

	path := tst.MustCreateTmpFile(t, "#!/bin/bash\necho -n OK", true, "busy-script.sh")

	// Hold the script open for writing so exec fails with ETXTBSY, the same
	// way a concurrently forked child holds the fd between its fork and exec
	// (golang/go#22315). Release it while the command retries.
	busyFd, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	require.NoError(t, err, "should reopen script for writing")

	go func() {
		time.Sleep(30 * time.Millisecond)
		_ = busyFd.Close()
	}()

	cmd := local.NewCommand(tst.Settings(), path)

	err = cmd.Run(context.Background())

	require.NoError(t, err, "run should succeed after ETXTBSY retries")
	require.Equal(t, "OK", string(cmd.StdoutBytes()), "should capture script output")
}

func TestCommandPipe(t *testing.T) {
	tst := tests.ShouldNewIntegrationTest(
		t,
		"LocalRunPipe",
		tests.TestWithParallelRun(true),
	)

	cmd := local.NewCommand(
		tst.Settings(),
		"bash",
		"-c",
		`echo "Goodbye world" | sed "s/Goodbye/Hello/g"`,
	)

	err := cmd.Run(context.Background())

	require.NoError(t, err, "should run")
	require.Equal(t, "Hello world", string(cmd.StdoutBytes()), "should equal stdout")
	require.Len(t, cmd.StderrBytes(), 0, "should no std err")
}
