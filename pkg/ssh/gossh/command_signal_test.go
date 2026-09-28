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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "github.com/deckhouse/lib-gossh"
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

// remoteProcessPGID returns the process group of the process whose command line
// starts with marker (the command itself, not its wrappers)
func remoteProcessPGID(t *testing.T, container *tests.TestContainerWrapper, marker string) int {
	t.Helper()

	for _, line := range remoteProcessLines(t, container, marker) {
		// pid pgid user args...
		fields := strings.Fields(line)
		if len(fields) < 4 || strings.Join(fields[3:], " ") != marker {
			continue
		}

		pgid, err := strconv.Atoi(fields[1])
		require.NoError(t, err, "cannot parse pgid from ps line %q", line)
		return pgid
	}

	require.Failf(t, "process not found", "no process %q in container", marker)
	return 0
}

func requireEventuallyRemoteProcess(t *testing.T, container *tests.TestContainerWrapper, marker string) {
	t.Helper()

	require.Eventually(t, func() bool {
		return len(remoteProcessLines(t, container, marker)) > 0
	}, remoteProcessWait, remoteProcessTick, "process %q should be running in container", marker)
}

func requireEventuallyNoRemoteProcess(t *testing.T, container *tests.TestContainerWrapper, marker string) {
	t.Helper()

	var last []string
	require.Eventually(t, func() bool {
		last = remoteProcessLines(t, container, marker)
		return len(last) == 0
	}, remoteProcessWait, remoteProcessTick, "processes %q should be killed in container, still running:\n%s", marker, strings.Join(last, "\n"))
}

func requireRemoteProcessStays(t *testing.T, container *tests.TestContainerWrapper, marker string, d time.Duration) {
	t.Helper()

	require.Never(t, func() bool {
		return len(remoteProcessLines(t, container, marker)) == 0
	}, d, remoteProcessTick, "process %q should stay running in container", marker)
}

func TestCommandSudoSignals(t *testing.T) {
	test := tests.ShouldNewIntegrationTest(t, "TestCommandSudoSignals")

	sshClient, container := startContainerAndClientWithContainer(t, test)
	ctx := context.Background()

	// startSleep starts "sleep <seconds>" (a unique duration identifies the process
	// in the container) with a wait handler, so Start returns right away
	startSleep := func(t *testing.T, sshClient *Client, seconds int, sudo bool) (*SSHCommand, string, <-chan error) {
		t.Helper()

		marker := fmt.Sprintf("sleep %d", seconds)
		cmd := NewSSHCommand(sshClient, marker)
		if sudo {
			cmd.Sudo(ctx)
		} else {
			cmd.Cmd(ctx)
		}

		waitErrCh := make(chan error, 1)
		cmd.WithWaitHandler(func(err error) { waitErrCh <- err })

		require.NoError(t, cmd.Start())
		requireEventuallyRemoteProcess(t, container, marker)

		return cmd, marker, waitErrCh
	}

	t.Run("wrapper reports the process group of the command", func(t *testing.T) {
		cmd, marker, _ := startSleep(t, sshClient, 3001, true)
		defer cmd.Stop()

		info, ok := cmd.remoteProcess.wait(sudoProcessInfoWaitTimeout, nil)
		require.True(t, ok, "process group should be reported")
		require.Equal(t, remoteProcessPGID(t, container, marker), info.PGID, "reported pgid should be the pgid of the command")
		require.NotEmpty(t, info.StartTime)
	})

	t.Run("Stop kills the process group", func(t *testing.T) {
		cmd, marker, _ := startSleep(t, sshClient, 3002, true)

		cmd.Stop()

		requireEventuallyNoRemoteProcess(t, container, marker)
	})

	t.Run("Signal SIGABRT kills the process group", func(t *testing.T) {
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

	t.Run("context deadline kills the process group", func(t *testing.T) {
		marker := "sleep 3004"

		deadlineCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		cmd := NewSSHCommand(sshClient, marker)
		cmd.Sudo(deadlineCtx)

		err := cmd.Run(deadlineCtx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "context deadline exceeded")

		requireEventuallyNoRemoteProcess(t, container, marker)
	})

	t.Run("timeout kills the process group", func(t *testing.T) {
		marker := "sleep 3005"

		cmd := NewSSHCommand(sshClient, marker)
		cmd.Sudo(ctx)
		cmd.WithTimeout(5 * time.Second)

		require.NoError(t, cmd.Start())

		requireEventuallyNoRemoteProcess(t, container, marker)
	})

	t.Run("stale process group is not killed", func(t *testing.T) {
		cmd, marker, _ := startSleep(t, sshClient, 3006, true)

		info, ok := cmd.remoteProcess.wait(sudoProcessInfoWaitTimeout, nil)
		require.True(t, ok, "process group should be reported")

		// the same pgid started at another time: another process after pid reuse
		stale := remoteProcessInfo{PGID: info.PGID, StartTime: info.StartTime + "1"}
		require.NoError(t, cmd.killRemoteProcessGroup(stale, []gossh.Signal{gossh.SIGKILL}))
		requireRemoteProcessStays(t, container, marker, 3*time.Second)

		require.NoError(t, cmd.killRemoteProcessGroup(info, []gossh.Signal{gossh.SIGKILL}))
		requireEventuallyNoRemoteProcess(t, container, marker)
	})

	t.Run("client Stop kills the running command", func(t *testing.T) {
		stopTest := tests.ShouldNewIntegrationTest(t, "TestCommandSudoSignalsClientStop")
		stopClient := startClient(t, stopTest, container)

		_, marker, _ := startSleep(t, stopClient, 3007, true)

		stopClient.Stop()

		requireEventuallyNoRemoteProcess(t, container, marker)
	})

	t.Run("Stop kills a command started without sudo", func(t *testing.T) {
		cmd, marker, _ := startSleep(t, sshClient, 3008, false)

		cmd.Stop()

		requireEventuallyNoRemoteProcess(t, container, marker)
	})

	t.Run("output of a sudo command does not contain the process group", func(t *testing.T) {
		cmd := NewSSHCommand(sshClient, "echo hi; echo err >&2")
		cmd.Sudo(ctx)
		out, errOut, err := cmd.Output(ctx)
		require.NoError(t, err)
		require.Equal(t, "SUDO-SUCCESS\nhi\n", string(out))
		require.NotContains(t, string(errOut), sudoPGIDMarker)
		require.Contains(t, string(errOut), "err\n")

		cmd = NewSSHCommand(sshClient, "echo hi; echo err >&2")
		cmd.Sudo(ctx)
		combined, err := cmd.CombinedOutput(ctx)
		require.NoError(t, err)
		require.NotContains(t, string(combined), sudoPGIDMarker)
		require.Contains(t, string(combined), "SUDO-SUCCESS\nhi\n")

		// the stdout handler is fed by its own goroutine which may lag behind Run
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
			return len(lines) > 0
		}, 10*time.Second, 100*time.Millisecond, "stdout handler should get the output")
		linesMu.Lock()
		require.Equal(t, []string{"hi"}, lines, "stdout handler must not get the process group line")
		linesMu.Unlock()
	})
}
