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
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "github.com/deckhouse/lib-gossh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/deckhouse/lib-connection/pkg/tests"
)

const (
	remoteProcessWait = 30 * time.Second
	remoteProcessTick = 500 * time.Millisecond
)

// remoteProcessLines returns the "ps" lines of the container whose command line
// contains marker: the command itself and the sudo/shell wrappers around it
func remoteProcessLines(t *testing.T, container *tests.TestContainerWrapper, marker string) []string {
	t.Helper()

	out, err := container.Container.ExecToContainerWithOut("list processes", "ps", "-eo", "pid,pgid,user,args")
	require.NoError(t, err, "cannot list processes in container")

	lines := make([]string, 0)
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, marker) && !strings.Contains(line, "ps -eo") {
			lines = append(lines, strings.TrimSpace(line))
		}
	}

	return lines
}

func requireEventuallyRemoteProcess(t *testing.T, container *tests.TestContainerWrapper, marker string) {
	t.Helper()

	require.Eventually(t, func() bool {
		return len(remoteProcessLines(t, container, marker)) > 0
	}, remoteProcessWait, remoteProcessTick, "process %q should be running in container", marker)
}

func requireEventuallyNoRemoteProcess(t *testing.T, container *tests.TestContainerWrapper, marker string) {
	t.Helper()

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		lines := remoteProcessLines(t, container, marker)
		assert.Empty(c, lines, "processes %q should be killed in container, still running:\n%s", marker, strings.Join(lines, "\n"))
	}, remoteProcessWait, remoteProcessTick)
}

func TestCommandSudoSignals(t *testing.T) {
	test := tests.ShouldNewIntegrationTest(t, "TestCommandSudoSignals")

	sshClient, container := startContainerAndClientWithContainer(t, test)
	ctx := context.Background()

	// startCommand starts cmdLine with a wait handler, so Start returns right away,
	// marker identifies the process in the container
	startCommand := func(t *testing.T, sshClient *Client, cmdLine, marker string, sudo bool) (*SSHCommand, <-chan error) {
		t.Helper()

		cmd := NewSSHCommand(sshClient, cmdLine)
		if sudo {
			cmd.Sudo(ctx)
		} else {
			cmd.Cmd(ctx)
		}

		waitErrCh := make(chan error, 1)
		cmd.WithWaitHandler(func(err error) { waitErrCh <- err })

		require.NoError(t, cmd.Start())
		requireEventuallyRemoteProcess(t, container, marker)
		if sudo {
			require.Eventually(t, cmd.sudoStarted.Load, remoteProcessWait, 100*time.Millisecond, "sudo wrapper should start")
		}

		return cmd, waitErrCh
	}

	startSleep := func(t *testing.T, sshClient *Client, seconds int, sudo bool) (*SSHCommand, string, <-chan error) {
		t.Helper()

		marker := fmt.Sprintf("sleep %d", seconds)
		cmd, waitErrCh := startCommand(t, sshClient, marker, marker, sudo)
		return cmd, marker, waitErrCh
	}

	t.Run("Stop kills the command", func(t *testing.T) {
		cmd, marker, _ := startSleep(t, sshClient, 3001, true)

		cmd.Stop()

		requireEventuallyNoRemoteProcess(t, container, marker)
	})

	t.Run("Stop kills a command which ignores SIGINT", func(t *testing.T) {
		marker := "sleep 3002"
		cmd, _ := startCommand(t, sshClient, `trap "" INT; `+marker, marker, true)

		cmd.Stop()

		requireEventuallyNoRemoteProcess(t, container, marker)
	})

	t.Run("Signal SIGABRT kills the command", func(t *testing.T) {
		cmd, marker, waitErrCh := startSleep(t, sshClient, 3003, true)

		require.NoError(t, cmd.Signal(gossh.SIGABRT))

		requireEventuallyNoRemoteProcess(t, container, marker)

		select {
		case err := <-waitErrCh:
			require.Error(t, err, "command should exit because of the signal")
		case <-time.After(remoteProcessWait):
			require.Fail(t, "wait handler should be called after the signal")
		}

		require.ErrorIs(t, cmd.Signal(gossh.SIGKILL), os.ErrProcessDone, "signal to an exited command should report that")
	})

	t.Run("context deadline returns the context error", func(t *testing.T) {
		for i := range 5 {
			deadlineCtx, cancel := context.WithTimeout(ctx, time.Second)

			cmd := NewSSHCommand(sshClient, fmt.Sprintf("sleep %d", 3010+i))
			cmd.Sudo(deadlineCtx)

			err := cmd.Run(deadlineCtx)
			cancel()
			require.ErrorIs(t, err, context.DeadlineExceeded, "run %d", i)
		}
	})

	t.Run("context deadline kills a command which ignores SIGINT", func(t *testing.T) {
		marker := "sleep 3004"

		deadlineCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		cmd := NewSSHCommand(sshClient, `trap "" INT; `+marker)
		cmd.Sudo(deadlineCtx)

		err := cmd.Run(deadlineCtx)
		require.ErrorIs(t, err, context.DeadlineExceeded)

		requireEventuallyNoRemoteProcess(t, container, marker)
	})

	t.Run("timeout kills the command", func(t *testing.T) {
		marker := "sleep 3005"

		cmd := NewSSHCommand(sshClient, marker)
		cmd.Sudo(ctx)
		cmd.WithTimeout(5 * time.Second)

		require.NoError(t, cmd.Start())

		requireEventuallyNoRemoteProcess(t, container, marker)
	})

	t.Run("closed session kills the command after sudo is killed", func(t *testing.T) {
		cmd, marker, _ := startSleep(t, sshClient, 3006, true)

		// sshd signals as the SSH user: only sudo is killed
		require.NoError(t, cmd.session.Signal(gossh.SIGKILL))
		cmd.closeSession()

		requireEventuallyNoRemoteProcess(t, container, marker)
	})

	t.Run("client Stop kills the running command", func(t *testing.T) {
		stopTest := tests.ShouldNewIntegrationTest(t, "TestCommandSudoSignalsClientStop")
		stopClient := startClient(t, stopTest, container)

		_, marker, _ := startSleep(t, stopClient, 3007, true)

		stopClient.Stop()

		requireEventuallyNoRemoteProcess(t, container, marker)
	})

	t.Run("client restart kills the running command", func(t *testing.T) {
		restartTest := tests.ShouldNewIntegrationTest(t, "TestCommandSudoSignalsClientRestart")
		restartClient := startClient(t, restartTest, container)

		_, marker, _ := startSleep(t, restartClient, 3008, true)

		require.NoError(t, restartClient.Start(ctx))

		requireEventuallyNoRemoteProcess(t, container, marker)
	})

	t.Run("Stop kills a command started without sudo", func(t *testing.T) {
		cmd, marker, _ := startSleep(t, sshClient, 3009, false)

		cmd.Stop()

		requireEventuallyNoRemoteProcess(t, container, marker)
	})

	t.Run("Stop of a command which was not started returns immediately", func(t *testing.T) {
		cmd := NewSSHCommand(sshClient, "sleep 3020")
		cmd.Sudo(ctx)
		defer cmd.closeSession()

		start := time.Now()
		cmd.Stop()
		require.Less(t, time.Since(start), 2*time.Second)
	})

	t.Run("output of a sudo command is not changed by the wrapper", func(t *testing.T) {
		cmd := NewSSHCommand(sshClient, "echo hi; echo err >&2")
		cmd.Sudo(ctx)
		out, errOut, err := cmd.Output(ctx)
		require.NoError(t, err)
		require.Equal(t, "SUDO-SUCCESS\nhi\n", string(out))
		require.Contains(t, string(errOut), "err\n")

		cmd = NewSSHCommand(sshClient, "echo hi; exit 3")
		cmd.Sudo(ctx)
		_, _, err = cmd.Output(ctx)
		var exitErr *gossh.ExitError
		require.ErrorAs(t, err, &exitErr)
		require.Equal(t, 3, exitErr.ExitStatus())

		// the stdout handler gets stderr too once sudo has started, in any order
		var (
			linesMu sync.Mutex
			lines   []string
		)
		cmd = NewSSHCommand(sshClient, "echo hi; echo err >&2")
		cmd.Sudo(ctx)
		cmd.WithStdoutHandler(func(line string) {
			linesMu.Lock()
			defer linesMu.Unlock()
			lines = append(lines, line)
		})
		require.NoError(t, cmd.Run(ctx))
		require.Eventually(t, func() bool {
			linesMu.Lock()
			defer linesMu.Unlock()
			return slices.Contains(lines, "hi")
		}, 10*time.Second, 100*time.Millisecond, "stdout handler should get the output")
		linesMu.Lock()
		defer linesMu.Unlock()
		for _, line := range lines {
			require.Contains(t, []string{"hi", "err"}, line, "stdout handler got unexpected line")
		}
	})
}
