// Copyright 2024 Flant JSC
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

package local

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/settings"
)

var (
	_ connection.Command = &Command{}
)

type Command struct {
	settings settings.Settings

	used atomic.Bool

	cmdMu sync.RWMutex
	cmd   *exec.Cmd

	program string
	args    []string
	sudo    bool
	env     map[string]string
	timeout time.Duration

	onStart           func()
	stdoutLineHandler func(line string)
	stderrLineHandler func(line string)

	stdout []byte
	stderr []byte
}

func NewCommand(sett settings.Settings, program string, args ...string) *Command {
	return &Command{
		program:  program,
		args:     args,
		settings: sett,
	}
}

// retryOnTextFileBusy retries fn while it fails with ETXTBSY: a concurrently
// forked child of this process may hold a just-written script open between its
// fork and exec (golang/go#22315), which makes exec of that script fail until
// the child releases the fd.
func retryOnTextFileBusy(fn func() error) error {
	const (
		attempts = 10
		wait     = 10 * time.Millisecond
	)

	var err error
	for range attempts {
		err = fn()
		if !errors.Is(err, syscall.ETXTBSY) {
			return err
		}
		time.Sleep(wait)
	}
	return err
}

func (c *Command) Run(ctx context.Context) error {
	if !c.used.CompareAndSwap(false, true) {
		return fmt.Errorf("command instance reused")
	}

	return retryOnTextFileBusy(func() error { return c.run(ctx) })
}

func (c *Command) run(ctx context.Context) error {
	cmd, cancel := c.prepareCmd(ctx)
	defer cancel()

	wg := &sync.WaitGroup{}
	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe failed: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe failed: %v", err)
	}
	wg.Add(2)
	go c.scanLines(stdout, stdoutBuf, wg, c.stdoutLineHandler)
	go c.scanLines(stderr, stderrBuf, wg, c.stderrLineHandler)

	if err = cmd.Start(); err != nil {
		return fmt.Errorf("cmd start failed: %w", err)
	}

	if c.onStart != nil {
		c.onStart()
	}

	c.setCmd(cmd)

	wg.Wait() // Wait for stdout/stderr reads to complete first
	c.stdout = stdoutBuf.Bytes()
	c.stderr = stderrBuf.Bytes()
	return cmd.Wait()
}

func (c *Command) scanLines(
	stream io.Reader,
	buf *bytes.Buffer,
	wg *sync.WaitGroup,
	handler func(string),
) {
	defer wg.Done()

	scan := bufio.NewScanner(stream)
	for scan.Scan() {
		line := scan.Text()
		buf.WriteString(line)
		if handler != nil {
			handler(line)
		}
	}
	if err := scan.Err(); err != nil && !errors.Is(err, os.ErrClosed) {
		// a failed cmd.Start (e.g. ETXTBSY retry) closes the pipes before
		// the scanners get any data; that is not worth an error log
		c.settings.Logger().ErrorContext(context.Background(), fmt.Sprintf("scan cmd output failed: %v\n", err))
	}
}

func (c *Command) OnCommandStart(fn func()) {
	c.onStart = fn
}

func (c *Command) Output(ctx context.Context) ([]byte, []byte, error) {
	if !c.used.CompareAndSwap(false, true) {
		return nil, nil, fmt.Errorf("command instance reused")
	}

	var stdout, stderr []byte
	err := retryOnTextFileBusy(func() error {
		var err error
		stdout, stderr, err = c.output(ctx)
		return err
	})
	return stdout, stderr, err
}

func (c *Command) output(ctx context.Context) ([]byte, []byte, error) {
	cmd, cancel := c.prepareCmd(ctx)
	defer cancel()

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("start %q: %w", c.program, err)
	}
	if c.onStart != nil {
		c.onStart()
	}

	if err := cmd.Wait(); err != nil {
		return nil, nil, err
	}
	return stdout.Bytes(), nil, nil // stderr is ignored to preserve compatibility with ssh frontend
}

func (c *Command) CombinedOutput(ctx context.Context) ([]byte, error) {
	if !c.used.CompareAndSwap(false, true) {
		return nil, fmt.Errorf("command instance reused")
	}

	var output []byte
	err := retryOnTextFileBusy(func() error {
		var err error
		output, err = c.combinedOutput(ctx)
		return err
	})
	return output, err
}

func (c *Command) combinedOutput(ctx context.Context) ([]byte, error) {
	cmd, cancel := c.prepareCmd(ctx)
	defer cancel()

	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %q: %w", c.program, err)
	}
	if c.onStart != nil {
		c.onStart()
	}

	if err := cmd.Wait(); err != nil {
		return nil, err
	}

	return output.Bytes(), nil
}

func (c *Command) Sudo(_ context.Context) {
	c.sudo = true
}

func (c *Command) WithTimeout(t time.Duration) {
	c.timeout = t
}

func (c *Command) WithEnv(env map[string]string) {
	c.env = env
}

func (c *Command) WithStdoutHandler(h func(line string)) {
	c.stdoutLineHandler = h
}

func (c *Command) WithStderrHandler(h func(line string)) {
	c.stderrLineHandler = h
}

func (c *Command) StdoutBytes() []byte {
	return c.stdout
}

func (c *Command) StderrBytes() []byte {
	return c.stderr
}

// The rest are no-ops for local execution
func (c *Command) Cmd(_ context.Context) {}

func (c *Command) WithSSHArgs(_ ...string) {}

func (c *Command) setCmd(cmd *exec.Cmd) {
	c.cmdMu.Lock()
	defer c.cmdMu.Unlock()

	c.cmd = cmd
}

func (c *Command) getCmd() *exec.Cmd {
	c.cmdMu.RLock()
	defer c.cmdMu.RUnlock()

	return c.cmd
}

func (c *Command) prepareCmd(ctx context.Context) (*exec.Cmd, context.CancelFunc) {
	bashBuiltins := []string{"bind", "type", "command", "let", "mapfile", "printf", "readarray", "ulimit"}

	program := c.program
	args := c.args
	if c.sudo {
		program = "sudo"
		args = append([]string{c.program}, c.args...)
	} else if slices.Contains(bashBuiltins, program) { // For shell built-in things we need to run bash
		program = "bash"
		args = []string{"-c", strings.Join(append([]string{c.program}, c.args...), " ")}
	}

	var cancel context.CancelFunc

	if c.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}

	cmd := exec.CommandContext(ctx, program, args...)
	if len(c.env) > 0 {
		cmd.Env = os.Environ()
		for k, v := range c.env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}

	c.settings.Logger().DebugContext(ctx, fmt.Sprintf("Command prepared: %#v\n", cmd))

	return cmd, cancel
}
