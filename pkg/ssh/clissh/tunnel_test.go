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

package clissh

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
)

func TestTunnelStopClosesPipesAndUnblocksLineConsumer(t *testing.T) {
	stdoutReadPipe, stdoutWritePipe, err := os.Pipe()
	require.NoError(t, err)
	stdinReadPipe, stdinWritePipe, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = stdoutReadPipe.Close()
		_ = stdoutWritePipe.Close()
		_ = stdinReadPipe.Close()
		_ = stdinWritePipe.Close()
	})

	tun := NewTunnel(newTestSettings(t), &session.Session{}, "L", "127.0.0.1:2222:127.0.0.1:22")
	tun.stdoutReadPipe = stdoutReadPipe
	tun.stdoutWritePipe = stdoutWritePipe
	tun.stdinReadPipe = stdinReadPipe
	tun.stdinWritePipe = stdinWritePipe

	consumerDone := make(chan struct{})
	go func() {
		tun.consumeLines(stdoutReadPipe, nil)
		close(consumerDone)
	}()

	tun.Stop()
	tun.Stop()

	select {
	case <-consumerDone:
	case <-time.After(time.Second):
		require.FailNow(t, "Stop must close stdout read pipe and unblock consumeLines")
	}

	_, err = stdoutWritePipe.Write([]byte("line\n"))
	require.Error(t, err, "Stop must close stdout write pipe")

	_, err = stdinWritePipe.Write([]byte("line\n"))
	require.Error(t, err, "Stop must close stdin write pipe")

	errCh := make(chan error, 1)
	go func() {
		_, readErr := stdinReadPipe.Read(make([]byte, 1))
		errCh <- readErr
	}()

	select {
	case err = <-errCh:
		errIs := errors.Is(err, os.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
		require.True(t, errIs, "Stop must close stdin read pipe, got %v", err)
	case <-time.After(time.Second):
		require.FailNow(t, "Stop must close stdin read pipe")
	}
}

func TestTunnelStopKillsProcessWithoutHealthMonitor(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})

	tun := NewTunnel(newTestSettings(t), &session.Session{}, "L", "127.0.0.1:2222:127.0.0.1:22")
	tun.sshCmd = cmd

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	tun.Stop()

	select {
	case <-waitCh:
	case <-time.After(time.Second):
		require.FailNow(t, "Stop must kill ssh process without HealthMonitor")
	}
}

func TestTunnelStopWithoutSessionStopsHealthMonitor(t *testing.T) {
	tun := NewTunnel(newTestSettings(t), nil, "L", "127.0.0.1:2222:127.0.0.1:22")

	monitorDone := make(chan struct{})
	go func() {
		tun.HealthMonitor(make(chan error))
		close(monitorDone)
	}()

	tun.Stop()

	select {
	case <-monitorDone:
	case <-time.After(time.Second):
		require.FailNow(t, "Stop must stop HealthMonitor even when session is missing")
	}
}

func newTestSettings(t *testing.T) settings.Settings {
	t.Helper()
	return settings.NewBaseProviders(settings.ProviderParams{
		TmpDir: t.TempDir(),
	})
}
