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
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	gossh "github.com/deckhouse/lib-gossh"
	"github.com/stretchr/testify/require"
)

// bareDollarRe matches "$name", "$N", "$$" and "$-": the login shell started by
// "sudo -i" expands them before bash gets the command
var bareDollarRe = regexp.MustCompile(`\$[A-Za-z0-9_$-]`)

const (
	testWrapperGrace = time.Second
	testWrapperWait  = 5 * time.Second
)

func TestSudoWrapperScriptIsSafeForSudoLoginShell(t *testing.T) {
	script := sudoWrapperScript("sleep 1", sudoStopGracePeriod)

	require.NotContains(t, script, "'", "script is embedded into a single-quoted bash -c argument")
	require.Empty(t, bareDollarRe.FindAllString(script, -1), "only ${name} and $(...) survive the sudo -i login shell")
	require.Contains(t, script, "while [ ${__i} -lt 50 ]", "grace period is 50 ticks of 0.1s")
}

func TestSudoControlLine(t *testing.T) {
	line, err := sudoControlLine(gossh.SIGKILL)
	require.NoError(t, err)
	require.Equal(t, "KILL\n", line)

	_, err = sudoControlLine(gossh.Signal("KILL; echo"))
	require.Error(t, err)
}

// sudoLoginShellEscape escapes the command the way "sudo -i" passes it to the login shell
func sudoLoginShellEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		isAlnum := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !isAlnum && r != '_' && r != '-' && r != '$' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

type localWrapper struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bytes.Buffer
	stderr *bytes.Buffer
	done   chan error
}

// startLocalWrapper runs the wrapper for cmdLine with the local bash as "sudo -i" does it
func startLocalWrapper(t *testing.T, cmdLine string) *localWrapper {
	t.Helper()

	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}

	script := sudoWrapperScript(cmdLine, testWrapperGrace)
	w := &localWrapper{
		cmd:    exec.Command("sh", "-c", "bash -c "+sudoLoginShellEscape(script)),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
		done:   make(chan error, 1),
	}
	w.cmd.Stdout = w.stdout
	w.cmd.Stderr = w.stderr

	var err error
	w.stdin, err = w.cmd.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, w.cmd.Start())

	go func() { w.done <- w.cmd.Wait() }()
	t.Cleanup(func() {
		_ = w.stdin.Close()
		select {
		case <-w.done:
		case <-time.After(10 * time.Second):
			_ = w.cmd.Process.Kill()
		}
	})

	return w
}

// exitCode waits for the wrapper and returns its exit code
func (w *localWrapper) exitCode(t *testing.T) int {
	t.Helper()

	select {
	case err := <-w.done:
		w.done <- err
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		require.NoError(t, err)
		return 0
	case <-time.After(testWrapperWait):
		require.FailNow(t, "wrapper did not exit", "in %s", testWrapperWait)
		return -1
	}
}

func TestSudoWrapperScript(t *testing.T) {
	t.Run("output and exit code of the command are kept", func(t *testing.T) {
		w := startLocalWrapper(t, `echo hi; echo err >&2; exit 3`)

		require.Equal(t, 3, w.exitCode(t))
		require.Equal(t, "SUDO-SUCCESS\nhi\n", w.stdout.String())
		require.Equal(t, "err\n", w.stderr.String())
	})

	t.Run("closed stdin kills a command which ignores SIGINT", func(t *testing.T) {
		w := startLocalWrapper(t, `trap "" INT; while :; do sleep 0.1; done`)
		time.Sleep(300 * time.Millisecond)

		start := time.Now()
		require.NoError(t, w.stdin.Close())

		require.Equal(t, 137, w.exitCode(t))
		require.GreaterOrEqual(t, time.Since(start), testWrapperGrace/2, "SIGKILL is sent after the grace period")
		require.Equal(t, "SUDO-SUCCESS\n", w.stdout.String())
		require.Empty(t, w.stderr.String(), "wrapper must not report the killed job")
	})

	t.Run("closed stdin stops a command with SIGINT first", func(t *testing.T) {
		w := startLocalWrapper(t, `trap "echo got-int; exit 5" INT; while :; do sleep 0.1; done`)
		time.Sleep(300 * time.Millisecond)

		require.NoError(t, w.stdin.Close())

		require.Equal(t, 5, w.exitCode(t))
		require.Equal(t, "SUDO-SUCCESS\ngot-int\n", w.stdout.String())
	})

	t.Run("signal from stdin is sent to the command", func(t *testing.T) {
		w := startLocalWrapper(t, `sleep 30`)
		time.Sleep(300 * time.Millisecond)

		line, err := sudoControlLine(gossh.SIGKILL)
		require.NoError(t, err)
		_, err = io.WriteString(w.stdin, line)
		require.NoError(t, err)

		require.Equal(t, 137, w.exitCode(t))
	})

	t.Run("unknown lines on stdin are ignored", func(t *testing.T) {
		w := startLocalWrapper(t, `sleep 0.5; echo done`)

		_, err := io.WriteString(w.stdin, "PING\nNOSUCHSIG\n")
		require.NoError(t, err)

		require.Equal(t, 0, w.exitCode(t))
		require.Equal(t, "SUDO-SUCCESS\ndone\n", w.stdout.String())
	})

	t.Run("command does not read stdin of the session", func(t *testing.T) {
		w := startLocalWrapper(t, `cat; echo cat-done`)

		require.Equal(t, 0, w.exitCode(t))
		require.Equal(t, "SUDO-SUCCESS\ncat-done\n", w.stdout.String())
	})

	t.Run("background process of a finished command is not killed", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), "survived")
		w := startLocalWrapper(t, `(sleep 1; touch `+marker+`) >/dev/null 2>&1 & echo started`)

		require.Equal(t, 0, w.exitCode(t))
		// the session ends after the command, Wait has closed stdin already
		_ = w.stdin.Close()

		require.Eventually(t, func() bool {
			_, err := os.Stat(marker)
			return err == nil
		}, 5*time.Second, 100*time.Millisecond, "background process should finish its work")
	})
}
