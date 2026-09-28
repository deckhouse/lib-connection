package gossh

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

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/retry"
	gossh "github.com/deckhouse/lib-gossh"
	"github.com/name212/govalue"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/ssh/utils"
)

var (
	_ connection.Command = &SSHCommand{}
)

var (
	// sudoProcessInfoWaitTimeout bounds waiting for the sudo wrapper to report the
	// process group of the command before a signal is sent to it
	sudoProcessInfoWaitTimeout = 10 * time.Second
	// remoteKillTimeout bounds the remote "kill" run for a sudo command
	remoteKillTimeout = 20 * time.Second
	// remoteKillSessionLoopParamsOps bound the session creation for the remote
	// "kill": the connection may be already dead, the signal is best effort
	remoteKillSessionLoopParamsOps = []retry.ParamsBuilderOpt{
		retry.WithWait(time.Second),
		retry.WithAttempts(3),
	}
)

type SSHCommand struct {
	sshClient *Client
	session   *gossh.Session

	Name string
	Args []string
	Env  []string

	SSHArgs []string

	stdoutPipeFile io.Reader
	stderrPipeFile io.Reader
	StdoutSplitter bufio.SplitFunc

	StdinPipe bool
	Stdin     io.WriteCloser

	// Matchers are shared by the stdout and stderr readers (the sudo password
	// prompt comes on stderr), matchersMu serializes their use
	Matchers     []*utils.ByteSequenceMatcher
	MatchHandler func(pattern string) string
	matchersMu   sync.Mutex

	onCommandStart func()
	stderrHandler  func(string)
	stdoutHandler  func(string)

	WaitHandler func(err error)

	out      *bytes.Buffer
	err      *bytes.Buffer
	combined *singleWriter

	OutBytes bytes.Buffer
	ErrBytes bytes.Buffer

	stop   atomic.Bool
	waitCh chan struct{}
	stopCh chan struct{}

	// exited is set when the remote process has exited (or the session is gone),
	// exitedCh is closed at the same time
	exited   atomic.Bool
	exitedCh chan struct{}

	lockWaitError sync.RWMutex
	waitError     error
	killError     error

	cmd     string
	timeout time.Duration

	// sudo is set by Sudo: the command runs as root and cannot be signalled
	// through the session, see sudo_process.go
	sudo bool
	// remoteProcess is the process group of the sudo command reported by the wrapper
	remoteProcess *remoteProcess
	// signalViaSessionOnly forces the session signal request for a sudo command,
	// it is set for the remote "kill" commands themselves
	signalViaSessionOnly bool
	// startHost is the host the command was started on, a remote "kill" is run
	// only while the client is connected to the same host
	startHost string

	ctx       context.Context
	Cancel    func() error
	ctxResult <-chan error
	wg        sync.WaitGroup
}

func NewSSHCommand(client *Client, name string, arg ...string) *SSHCommand {
	return newSSHCommand(client, name, false, arg...)
}

func newSSHCommand(client *Client, name string, allowStopped bool, arg ...string) *SSHCommand {
	// todo move new session to Start()
	session, err := client.newSSHSession(allowStopped)
	if err != nil {
		client.settings.Logger().DebugContext(context.Background(), fmt.Sprintf("Cannot create new SSH session for command '%s': %v", name, err))
	}

	return newSSHCommandWithSession(client, session, name, arg...)
}

func newSSHCommandWithSession(client *Client, session *gossh.Session, name string, arg ...string) *SSHCommand {
	args := make([]string, len(arg))
	copy(args, arg)
	cmd := name + " "
	for i := range args {
		if !strings.HasPrefix(args[i], `"`) &&
			!strings.HasSuffix(args[i], `"`) &&
			strings.Contains(args[i], " ") {
			args[i] = strconv.Quote(args[i])
		}
	}

	return &SSHCommand{
		// Executor: process.NewDefaultExecutor(sess.Run(cmd)),
		sshClient: client,
		session:   session,
		Name:      name,
		Args:      args,
		Env:       os.Environ(),
		cmd:       cmd,
		exitedCh:  make(chan struct{}),
	}
}

func (c *SSHCommand) WithSSHArgs(args ...string) {
	c.SSHArgs = args
}

func (c *SSHCommand) OnCommandStart(fn func()) {
	c.onCommandStart = fn
}

func (c *SSHCommand) Start() error {
	// setup stream handlers
	ctx := context.Background()
	c.logDebugF(ctx, "Call start")
	if c.session == nil {
		return fmt.Errorf("ssh session not started")
	}

	err := c.SetupStreamHandlers()
	if err != nil {
		c.logDebugF(ctx, "Could not set up stream handlers: %s", err)
		return err
	}

	err = c.start()
	if err != nil {
		c.logDebugF(ctx, "Could not start: %v", err)
		return err
	}

	if c.WaitHandler != nil || c.timeout > 0 {
		c.ProcessWait()
		// wait only with timeout because WaitHandler run in long time commands like kube proxy
		if c.timeout > 0 {
			if c.waitCh != nil {
				<-c.waitCh
			} else {
				c.logDebugF(ctx, "Wait channel is nil. Possible bug. Returns immediately")
			}
		}
	} else {
		err = c.wait()
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *SSHCommand) start() error {
	if c.ctx != nil {
		select {
		case <-c.ctx.Done():
			return c.ctx.Err()
		default:
		}
	}

	if c.Cancel != nil && c.ctx != nil && c.ctx.Done() != nil {
		resultc := make(chan error, 1)
		c.ctxResult = resultc
		go c.watchCtx(resultc)
	}

	command := c.cmd + " " + strings.Join(c.Args, " ")

	c.startHost = c.sshClient.Session().Host()

	if err := c.session.Start(command); err != nil {
		return err
	}

	c.sshClient.registerCommand(c)

	return nil
}

func (c *SSHCommand) watchCtx(resultc chan<- error) {
	<-c.ctx.Done()

	var err error
	if c.Cancel != nil {
		if interruptErr := c.Cancel(); interruptErr == nil {
			// We appear to have successfully interrupted the command, so any
			// program behavior from this point may be due to ctx even if the
			// command exits with code 0.
			err = c.ctx.Err()
		} else if errors.Is(interruptErr, os.ErrProcessDone) {
			// The process already finished: we just didn't notice it yet.
			// (Perhaps c.Wait hadn't been called, or perhaps it happened to race with
			// c.ctx being canceled.) Don't inject a needless error.
		} else {
			err = interruptErr
		}
	}

	resultc <- err
}

func (c *SSHCommand) wait() error {
	waitCh := make(chan error, 1)

	go func() {
		err := c.session.Wait()
		c.markExited()
		waitCh <- err
	}()

	select {
	case err := <-c.ctxResult:
		// if c.ctxResult != nil {
		// 	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		// 		return nil
		// 	}
		// }
		return err
	case err := <-waitCh:
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *SSHCommand) ProcessWait() {
	waitErrCh := make(chan error, 1)
	c.waitCh = make(chan struct{}, 1)
	c.stopCh = make(chan struct{}, 1)

	ctx := context.Background()

	// wait for process in go routine
	go func() {
		waitErrCh <- c.wait()
	}()

	// todo need investigation for get rid of this gorutine. we need check to channel is stopped
	// and gourutine does not exit if we use timeout and command stopped before timeout exited
	// probably we can use timer or context instead of this goroutine
	go func() {
		if c.timeout > 0 {
			time.Sleep(c.timeout)
			if !c.stop.Load() && c.stopCh != nil {
				// todo ugly solution
				// here we check that channel is closed it is not correct
				select {
				case _, ok := <-c.stopCh:
					if !ok {
						c.logDebugF(ctx, "StopCh was closed and '%s' timeout exceeded. Possible goroutine not closed.", c.timeout)
						return
					}
				default:
					c.logDebugF(ctx, "StopCh is not close and '%s' timeout exceeded. Send stop", c.timeout)
				}

				c.stopCh <- struct{}{}
			}
		}
	}()

	// watch for wait or stop
	go func() {
		defer func() {
			close(c.waitCh)
			close(waitErrCh)
		}()
		// Wait until Stop() is called or/and Wait() is returning.
		for {
			select {
			case err := <-waitErrCh:
				if c.stop.Load() {
					// Ignore error if Stop() was called.
					return
				}
				c.setWaitError(err)
				if c.WaitHandler != nil {
					c.WaitHandler(c.waitError)
				}
				return
			case <-c.stopCh:
				// Prevent next readings from the closed channel.
				c.stopCh = nil
				// Stop() sends the signals itself, only the timeout has to kill here
				if !c.stop.CompareAndSwap(false, true) {
					continue
				}
				c.logDebugF(ctx, "Timeout exceeded. Killing")
				if err := c.signal(gossh.SIGKILL); err != nil && !errors.Is(err, os.ErrProcessDone) {
					c.killError = err
				}
			}
		}
	}()
}

func (c *SSHCommand) clientString() string {
	sessionString := "unknown"
	sess := c.sshClient.Session()
	if c.sshClient != nil && sess != nil {
		sessionString = sess.String()
	}

	return sessionString
}

func (c *SSHCommand) Run(ctx context.Context) error {
	c.logDebugF(ctx, "Call run")
	c.Cmd(ctx)

	if c.session == nil {
		return fmt.Errorf("ssh session not started")
	}

	defer c.closeSession()

	err := c.Start()
	if err != nil {
		return err
	}

	c.Stop()

	return c.WaitError()
}

func (c *SSHCommand) WaitError() error {
	defer c.lockWaitError.RUnlock()
	c.lockWaitError.RLock()
	return c.waitError
}

func (c *SSHCommand) StderrBytes() []byte {
	if len(c.ErrBytes.Bytes()) > 0 {
		return c.ErrBytes.Bytes()
	}

	if c.err != nil {
		return c.err.Bytes()
	}

	return nil
}

func (c *SSHCommand) StdoutBytes() []byte {
	if len(c.OutBytes.Bytes()) > 0 {
		return c.OutBytes.Bytes()
	}

	if c.out != nil {
		return c.out.Bytes()
	}

	return nil
}

func (c *SSHCommand) WithMatchers(matchers ...*utils.ByteSequenceMatcher) *SSHCommand {
	c.Matchers = make([]*utils.ByteSequenceMatcher, 0)
	c.Matchers = append(c.Matchers, matchers...)
	return c
}

func (c *SSHCommand) WithWaitHandler(waitHandler func(error)) *SSHCommand {
	c.WaitHandler = waitHandler
	return c
}

func (c *SSHCommand) OpenStdinPipe() *SSHCommand {
	c.StdinPipe = true
	return c
}

func (c *SSHCommand) WithMatchHandler(fn func(pattern string) string) *SSHCommand {
	c.MatchHandler = fn
	return c
}

func (c *SSHCommand) Sudo(ctx context.Context) {
	cmdLine := c.Name + " " + strings.Join(c.Args, " ")
	// the wrapper reports the process group of the command first (see
	// sudo_process.go), the marker line is stripped from the output
	sudoCmdLine := fmt.Sprintf(
		`sudo -p SudoPassword -H -S -i bash -c '%s; echo SUDO-SUCCESS && %s'`,
		sudoWrapperPGIDSnippet,
		cmdLine,
	)

	c.cmd = sudoCmdLine
	c.sudo = true
	c.remoteProcess = newRemoteProcess()
	c.Cmd(ctx)

	c.WithMatchers(
		utils.NewByteSequenceMatcher("SudoPassword"),
		utils.NewByteSequenceMatcher("SUDO-SUCCESS").WaitNonMatched(),
	)
	c.OpenStdinPipe()

	passSent := false
	c.WithMatchHandler(func(pattern string) string {
		logger := c.sshClient.settings.Logger()
		if pattern == "SudoPassword" {
			c.logDebugF(ctx, "Send become pass to cmd")
			becomePass := c.sshClient.Session().BecomePass

			var err error
			_, err = c.Stdin.Write([]byte(becomePass + "\n"))
			if err != nil {
				logger.ErrorContext(ctx, fmt.Sprintf("Got error from sending pass to stdin for '%s': %v", c.clientString(), err))
			}
			if !passSent {
				passSent = true
			} else {
				// Second prompt is error!
				logger.ErrorContext(ctx, "Bad sudo password.")
			}
			return "reset"
		}
		if pattern == "SUDO-SUCCESS" {
			c.logDebugF(ctx, "Got SUCCESS for sudo password")
			// the process group is reported before this marker: if it is not
			// captured by now, it will never be
			c.remoteProcess.markUnavailable()
			if c.onCommandStart != nil {
				c.onCommandStart()
			}
			return "done"
		}
		return ""
	})
}

func (c *SSHCommand) WithStdoutHandler(handler func(string)) {
	c.stdoutHandler = handler
}

func (c *SSHCommand) WithStderrHandler(handler func(string)) {
	c.stderrHandler = handler
}

func (c *SSHCommand) Cmd(ctx context.Context) {
	if ctx != nil {
		c.ctx = ctx
	}
	c.Cancel = func() error {
		return c.signal(gossh.SIGINT)
	}
}

func (c *SSHCommand) Output(ctx context.Context) ([]byte, []byte, error) {
	c.Cmd(ctx)
	if c.session == nil {
		return nil, nil, fmt.Errorf("ssh session not started")
	}
	defer c.closeSession()

	if c.out == nil {
		c.out = new(bytes.Buffer)
	} else {
		c.out.Reset()
	}

	if c.err == nil {
		c.err = new(bytes.Buffer)
	} else {
		c.err.Reset()
	}

	var err error
	c.stdoutPipeFile, err = c.session.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("open stdout pipe '%s': %w", c.Name, err)
	}

	c.stderrPipeFile, err = c.session.StderrPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("open stderr pipe '%s': %w", c.Name, err)
	}

	err = c.Start()
	if isContextError(err) {
		return nil, nil, err
	}

	c.wg.Wait()

	return c.out.Bytes(), c.err.Bytes(), err
}

func isContextError(err error) bool {
	if err == nil {
		return false
	}

	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

type singleWriter struct {
	b  bytes.Buffer
	mu sync.Mutex
}

func (w *singleWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (c *SSHCommand) CombinedOutput(ctx context.Context) ([]byte, error) {
	c.Cmd(ctx)
	if c.session == nil {
		return nil, fmt.Errorf("ssh session not started")
	}

	defer c.closeSession()

	if c.out == nil {
		c.out = new(bytes.Buffer)
	} else {
		c.out.Reset()
	}

	if c.err == nil {
		c.err = new(bytes.Buffer)
	} else {
		c.err.Reset()
	}

	var err error
	c.stdoutPipeFile, err = c.session.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("open stdout pipe '%s': %w", c.Name, err)
	}

	c.stderrPipeFile, err = c.session.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("open stderr pipe '%s': %w", c.Name, err)
	}
	var co singleWriter
	c.combined = &co

	err = c.Start()
	if isContextError(err) {
		return nil, err
	}

	c.wg.Wait()
	return c.combined.b.Bytes(), err
}

func (c *SSHCommand) WithTimeout(timeout time.Duration) {
	c.timeout = timeout
}

func (c *SSHCommand) WithEnv(env map[string]string) {
	c.Env = make([]string, 0, len(env))
	for k, v := range env {
		c.Env = append(c.Env, fmt.Sprintf("%s=%s", k, v))
	}
}

func (c *SSHCommand) CaptureStdout(buf *bytes.Buffer) *SSHCommand {
	if buf != nil {
		c.out = buf
	} else {
		c.out = &bytes.Buffer{}
	}
	return c
}

func (c *SSHCommand) CaptureStderr(buf *bytes.Buffer) *SSHCommand {
	if buf != nil {
		c.err = buf
	} else {
		c.err = &bytes.Buffer{}
	}
	return c
}

func (c *SSHCommand) SetupStreamHandlers() error {
	// stderr goes to console (commented because ssh writes only "Connection closed" messages to stderr)
	// c.Cmd.Stderr = os.Stderr
	// connect console's stdin
	// c.Cmd.Stdin = os.Stdin

	ctx := context.Background()

	// setup stdout stream handlers
	if c.session != nil && c.out == nil && c.stdoutHandler == nil && len(c.Matchers) == 0 {
		c.session.Stdout = os.Stdout
		c.session.Stdout = &c.OutBytes
		c.session.Stderr = &c.ErrBytes
		return nil
	}

	var err error
	var stdoutHandlerWritePipe *os.File
	var stdoutHandlerReadPipe *os.File
	if c.out != nil || c.stdoutHandler != nil || len(c.Matchers) > 0 {
		if c.out == nil {
			c.out = new(bytes.Buffer)
		}

		if c.stdoutPipeFile == nil {
			var err error
			c.stdoutPipeFile, err = c.session.StdoutPipe()
			if err != nil {
				return fmt.Errorf("open stdout pipe '%s': %w", c.Name, err)
			}
		}

		// create pipe for StdoutHandler
		if c.stdoutHandler != nil {
			stdoutHandlerReadPipe, stdoutHandlerWritePipe, err = os.Pipe()
			if err != nil {
				return fmt.Errorf("unable to create os pipe for stdoutHandler: %s", err)
			}
		}
	}

	var stderrReadPipe io.Reader
	var stderrHandlerWritePipe *os.File
	var stderrHandlerReadPipe *os.File
	if c.err != nil || c.stderrHandler != nil || len(c.Matchers) > 0 {
		if c.err == nil {
			c.err = new(bytes.Buffer)
		}

		if c.stderrPipeFile == nil {
			var err error
			c.stderrPipeFile, err = c.session.StderrPipe()
			if err != nil {
				return fmt.Errorf("open stdout pipe '%s': %w", c.Name, err)
			}
		}

		// create pipe for StderrHandler
		if c.stderrHandler != nil {
			stderrHandlerReadPipe, stderrHandlerWritePipe, err = os.Pipe()
			if err != nil {
				return fmt.Errorf("unable to create os pipe for stderrHandler: %s", err)
			}
		}
	}

	if c.StdinPipe {
		c.Stdin, err = c.session.StdinPipe()
		if err != nil {
			return fmt.Errorf("open stdin pipe: %v", err)
		}
	}

	// Start reading from stdout of a command.
	// Wait until all matchers are done and then:
	// - Copy to os.Stdout if live output is enabled
	// - Copy to buffer if capture is enabled
	// - Copy to pipe if StdoutHandler is set
	c.wg.Add(2)
	go func() {
		c.readFromStreams(c.stdoutPipeFile, stdoutHandlerWritePipe, false)
	}()

	// sudo hack, because of password prompt is sent to STDERR, not STDOUT
	go func() {
		c.readFromStreams(c.stderrPipeFile, stdoutHandlerWritePipe, true)
	}()

	go func() {
		if c.stdoutHandler == nil {
			c.logDebugF(ctx, "stdout read pipe not set. Consumer does not start")
			return
		}
		c.ConsumeLines(stdoutHandlerReadPipe, c.stdoutHandler)
		c.logDebugF(ctx, "Stop lines consumer")
	}()

	// Start reading from stderr of a command.
	// Copy to os.Stderr if live output is enabled
	// Copy to buffer if capture is enabled
	// Copy to pipe if StderrHandler is set
	go func() {
		if stderrReadPipe == nil {
			c.logDebugF(ctx, "stdterr read pipe not set. Pipe reader does not start")
			return
		}

		c.logDebugF(ctx, "Start reading from stderr pipe")
		defer c.logDebugF(ctx, "Stop reading from stderr pipe")

		buf := make([]byte, 16)
		for {
			n, err := stderrReadPipe.Read(buf)

			// TODO logboek
			if c.sshClient.settings.IsDebug() {
				os.Stderr.Write(buf[:n])
			}
			if c.err != nil {
				c.err.Write(buf[:n])
			}
			if c.stderrHandler != nil {
				_, _ = stderrHandlerWritePipe.Write(buf[:n])
			}

			if err == io.EOF {
				break
			}
		}
	}()

	go func() {
		if c.stderrHandler == nil {
			c.logDebugF(ctx, "stdterr line consumer not set. Consumer does not start")
			return
		}
		c.ConsumeLines(stderrHandlerReadPipe, c.stderrHandler)
		c.logDebugF(ctx, "Stop stdterr line consumer")
	}()

	return nil
}

func (c *SSHCommand) readFromStreams(stdoutReadPipe io.Reader, stdoutHandlerWritePipe io.Writer, isError bool) {
	ctx := context.Background()
	defer c.logDebugF(ctx, "readFromStreams stopped")
	defer c.wg.Done()

	if govalue.Nil(stdoutReadPipe) {
		c.logDebugF(ctx, "stdout pipe is nil")
		return
	}

	c.logDebugF(ctx, "Start read from streams")

	// the sudo wrapper reports the process group of the command on stdout,
	// the marker line is consumed here and never reaches the consumers
	var processInfoCapture *markerLineCapture
	if !isError && c.remoteProcess != nil {
		processInfoCapture = newMarkerLineCapture(
			sudoPGIDMarker,
			sudoPGIDMarkerMaxLine,
			func(line []byte) {
				if err := c.remoteProcess.setFromMarkerLine(line); err != nil {
					c.logDebugF(ctx, "Cannot parse sudo process info: %v", err)
					return
				}
				info, _ := c.remoteProcess.get()
				c.logDebugF(ctx, "Got sudo process info: %s", info.String())
			},
			func() {
				c.logDebugF(ctx, "Sudo process info was not reported")
				c.remoteProcess.markUnavailable()
			},
		)
	}

	buf := make([]byte, 16)
	matchersDone := false
	errorsCount := 0
	for {
		n, err := stdoutReadPipe.Read(buf)
		if err != nil && err != io.EOF {
			c.logDebugF(ctx, "Error reading from stdout: %v", err)
			errorsCount++
			if errorsCount > 1000 {
				panic(fmt.Errorf("readFromStreams: too many errors, last error %v", err))
			}
			continue
		}

		chunk := buf[:n]
		if processInfoCapture != nil {
			chunk = processInfoCapture.Feed(chunk)
			if err == io.EOF {
				if withheld := processInfoCapture.Flush(); len(withheld) > 0 {
					chunk = append(append([]byte{}, chunk...), withheld...)
				}
			}
			n = len(chunk)
		}

		m := 0
		if !matchersDone {
			c.matchersMu.Lock()
			for _, matcher := range c.Matchers {
				m = matcher.Analyze(chunk)
				if matcher.IsMatched() {
					c.logDebugF(ctx, "Triggered match for '%s'", matcher.Pattern)
					// matcher is triggered
					if c.MatchHandler != nil {
						res := c.MatchHandler(matcher.Pattern)
						if res == "done" {
							matchersDone = true
							break
						}
						if res == "reset" {
							matcher.Reset()
						}
					}
				}
			}
			c.matchersMu.Unlock()

			// stdout for internal use, no copying to pipes until all Matchers are matched
			if !matchersDone {
				m = n
			}
		}
		// TODO logboek
		if c.sshClient.settings.IsDebug() {
			_, _ = os.Stdout.Write(chunk[m:n])
		}
		if c.out != nil && !isError {
			_, _ = c.out.Write(chunk)
		}

		if c.err != nil && isError {
			_, _ = c.err.Write(chunk)
		}

		if c.combined != nil {
			_, _ = c.combined.Write(chunk)
		}
		if c.stdoutHandler != nil {
			_, _ = stdoutHandlerWritePipe.Write(chunk[m:n])
		}

		if err == io.EOF {
			c.logDebugF(ctx, "readFromStreams: EOF")
			break
		}
	}
}

func (c *SSHCommand) ConsumeLines(r io.Reader, fn func(l string)) {
	scanner := bufio.NewScanner(r)
	if c.StdoutSplitter != nil {
		scanner.Split(c.StdoutSplitter)
	}
	for scanner.Scan() {
		text := scanner.Text()

		if fn != nil {
			fn(text)
		}

		if text != "" {
			c.logDebugF(context.Background(), "Line consumed: '%s'", text)
		}
	}
}

func (c *SSHCommand) Stop() {
	ctx := context.Background()
	c.logDebugF(ctx, "Running stop")

	if c.stop.Load() {
		c.logDebugF(ctx, "Already stopped")
		return
	}
	if c.session == nil {
		c.logDebugF(ctx, "Session not started yet")
		return
	}
	if c.cmd == "" {
		c.logDebugF(ctx, "Possible BUG: Call Executor.Stop with Cmd==nil")
		return
	}

	if !c.stop.CompareAndSwap(false, true) {
		c.logDebugF(ctx, "Already stopped")
		return
	}
	if c.stopCh != nil {
		c.logDebugF(ctx, "Send stop signal")
		close(c.stopCh)
	}
	c.logDebugF(ctx, "Stopped")
	c.logDebugF(ctx, "Sending SIGINT and SIGKILL...")
	if err := c.signal(gossh.SIGINT, gossh.SIGKILL); err != nil && !errors.Is(err, os.ErrProcessDone) {
		c.logDebugF(ctx, "Cannot signal: %v", err)
		c.killError = err
	}
	c.logDebugF(ctx, "Signals SIGINT and SIGKILL sent")
}

// Signal sends sig to the remote process.
//
// A command started with Sudo runs as root, the signal request of the SSH
// session reaches only the sudo process (see sudo_process.go), so such a
// command is signalled with a remote "kill" of its process group run through
// a separate sudo session. If the process group is unknown (the wrapper has
// not reported it, the host has changed since the start) the session signal
// request is sent instead. Returns os.ErrProcessDone if the process has exited.
func (c *SSHCommand) Signal(sig gossh.Signal) error {
	return c.signal(sig)
}

// signal sends sigs to the remote process in the given order, see Signal
func (c *SSHCommand) signal(sigs ...gossh.Signal) error {
	ctx := context.Background()

	if c.session == nil {
		return fmt.Errorf("ssh session not started")
	}

	if len(sigs) == 0 {
		return nil
	}

	if c.exited.Load() {
		c.logDebugF(ctx, "Process has exited. Skip sending %v", sigs)
		return os.ErrProcessDone
	}

	if !c.sudo || c.signalViaSessionOnly {
		return c.signalViaSession(sigs...)
	}

	proc, ok := c.remoteProcess.wait(sudoProcessInfoWaitTimeout, c.exitedCh)
	if c.exited.Load() {
		c.logDebugF(ctx, "Process has exited. Skip sending %v", sigs)
		return os.ErrProcessDone
	}

	if !ok {
		c.logDebugF(ctx, "Process group of sudo command is unknown. Send %v via session", sigs)
		return c.signalViaSession(sigs...)
	}

	if host := c.sshClient.Session().Host(); host != c.startHost {
		c.logDebugF(ctx, "Command was started on host '%s' but client connected to '%s'. Send %v via session", c.startHost, host, sigs)
		return c.signalViaSession(sigs...)
	}

	if err := c.killRemoteProcessGroup(proc, sigs); err != nil {
		c.logDebugF(ctx, "Remote kill failed: %v. Send %v via session", err, sigs)
		if sessionErr := c.signalViaSession(sigs...); sessionErr != nil {
			return errors.Join(err, sessionErr)
		}
		return err
	}

	return nil
}

func (c *SSHCommand) signalViaSession(sigs ...gossh.Signal) error {
	for _, sig := range sigs {
		if err := c.session.Signal(sig); err != nil {
			return fmt.Errorf("send %s via session: %w", sig, err)
		}
	}

	return nil
}

// killRemoteProcessGroup delivers sigs to the process group proc on the remote
// with a "kill" run as root through a new session, see remoteKillScript
func (c *SSHCommand) killRemoteProcessGroup(proc remoteProcessInfo, sigs []gossh.Signal) error {
	// the command may be killed because its context is done or the client is
	// stopping, the kill must not depend on the canceled contexts
	baseCtx := context.Background()
	if c.ctx != nil {
		baseCtx = context.WithoutCancel(c.ctx)
	}
	ctx, cancel := context.WithTimeout(baseCtx, remoteKillTimeout)
	defer cancel()

	c.logDebugF(ctx, "Sending %v to remote process group (%s)", sigs, proc.String())

	// the kill is allowed on a stopping client: Stop kills the running commands
	sess, err := c.sshClient.newSSHSessionWithParams(true, retry.NewEmptyParams(remoteKillSessionLoopParamsOps...))
	if err != nil {
		return fmt.Errorf("cannot open session for remote kill: %w", err)
	}

	killCmd := newSSHCommandWithSession(c.sshClient, sess, remoteKillScript(proc, sigs))
	killCmd.signalViaSessionOnly = true
	killCmd.Sudo(ctx)

	out, err := killCmd.CombinedOutput(ctx)
	outStr := string(out)

	switch {
	case strings.Contains(outStr, remoteKillDoneMarker):
		c.logDebugF(ctx, "Remote process group %s got %v", proc.String(), sigs)
		return nil
	case strings.Contains(outStr, remoteKillMismatchMarker):
		c.logDebugF(ctx, "Leader of remote process group %s was replaced by another process. Nothing to kill", proc.String())
		return nil
	case strings.Contains(outStr, remoteKillNoProcMarker):
		c.logDebugF(ctx, "Remote process group %s does not exist. Nothing to kill", proc.String())
		return nil
	}

	if err != nil {
		return fmt.Errorf("remote kill failed: %w; output: %s", err, strings.TrimSpace(outStr))
	}

	return fmt.Errorf("remote kill returned unexpected output: %s", strings.TrimSpace(outStr))
}

func (c *SSHCommand) markExited() {
	if !c.exited.CompareAndSwap(false, true) {
		return
	}

	close(c.exitedCh)
	c.sshClient.unregisterCommand(c)
}

func (c *SSHCommand) setWaitError(err error) {
	defer c.lockWaitError.Unlock()
	c.lockWaitError.Lock()
	c.waitError = err
}

func (c *SSHCommand) closeSession() {
	c.session.Close()
	c.sshClient.UnregisterSession(c.session)
	c.sshClient.unregisterCommand(c)
}

func (c *SSHCommand) logDebugF(ctx context.Context, format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	args := ""
	if len(c.Args) > 0 {
		args = strings.Join(c.Args, " ")
	}
	// the process group snippet of the sudo wrapper is too noisy for the logs
	cmd := strings.Replace(c.cmd, sudoWrapperPGIDSnippet, "<report process group>", 1)
	c.sshClient.settings.Logger().DebugContext(ctx, fmt.Sprintf("'%s' for cmd '%s' with args '%s' with client '%s'\n", msg, cmd, args, c.clientString()))
}
