// Copyright 2021 Flant JSC
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

package process

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/utils"
)

// exec.Cmd executor

/*
4 types for stdout:

live output or not.  copy to os.Stdout or not

wait for SUCCESS line?

capture output.  copy to bytes.Buffer or not

stdout handler.  buffered pipe to read output line by line with scanner.Scan


2 types for stderr

live stderr. Copy to os.Stderr or be quiet.

capture stderr. copy to bytes.Buffer For errors!


2 types of running:

execute and wait while finished

start in a background



What combinations do we really need?

SudoStart:    (kubectl proxy)
- live stderr
- live stdout until some line occurs
- wait for SUCCESS line
- stdout handler

SudoRun:     (bashible bundle, etc)
- live stdout and stderr
- capture stdout


Start:     (tunnels, agent)
- no live
- stdout handler
- wait until success


LiveRun:   (ssh-add)
- live output
- no capture

LiveOutput

NewCommand("ls", "-la").Live().Sudo().


proxyCmd := NewCommand("kube-proxy").EnableSudo().EnableLive().CaptureStdout(buf)

// run in background
err := proxyCmd.Start()

*/

type Executor struct {
	settings settings.Settings

	cmd *exec.Cmd

	Session *Session

	Live      bool
	StdinPipe bool

	Stdin io.WriteCloser

	Matchers     []*utils.ByteSequenceMatcher
	MatchHandler func(pattern string) string

	StdoutBuffer   *bytes.Buffer
	StdoutSplitter bufio.SplitFunc
	StdoutHandler  func(l string)

	pipesMutex     sync.Mutex
	stdoutPipeFile *os.File
	stderrPipeFile *os.File
	// Read ends of pipes must be closed to unblock goroutines stuck in Read().
	stdoutReadPipe        *os.File
	stderrReadPipe        *os.File
	stdoutHandlerReadPipe *os.File
	stderrHandlerReadPipe *os.File

	StderrBuffer   *bytes.Buffer
	StderrSplitter bufio.SplitFunc
	StderrHandler  func(l string)

	WaitHandler func(err error)

	started  atomic.Bool
	stop     atomic.Bool
	waitCh   chan struct{}
	stopCh   chan struct{}
	doneCh   chan struct{}
	stopOnce sync.Once

	lockWaitError sync.RWMutex
	waitError     error

	killError error

	timeout time.Duration
}

func NewDefaultExecutor(sett settings.Settings, cmd *exec.Cmd) *Executor {
	return NewExecutor(sett, DefaultSession, cmd)
}

func NewExecutor(sett settings.Settings, sess *Session, cmd *exec.Cmd) *Executor {
	return &Executor{
		Session:  sess,
		cmd:      cmd,
		settings: sett,
	}
}

func (e *Executor) EnableLive() *Executor {
	e.Live = true
	return e
}

func (e *Executor) OpenStdinPipe() *Executor {
	e.StdinPipe = true
	return e
}

func (e *Executor) WithStdoutHandler(stdoutHandler func(l string)) {
	e.StdoutHandler = stdoutHandler
}

func (e *Executor) WithStdoutSplitter(fn bufio.SplitFunc) *Executor {
	e.StdoutSplitter = fn
	return e
}

func (e *Executor) WithStderrHandler(stderrHandler func(l string)) {
	e.StderrHandler = stderrHandler
}

func (e *Executor) WithStderrSplitter(fn bufio.SplitFunc) *Executor {
	e.StderrSplitter = fn
	return e
}

func (e *Executor) WithWaitHandler(waitHandler func(error)) *Executor {
	e.WaitHandler = waitHandler
	return e
}

func (e *Executor) CaptureStdout(buf *bytes.Buffer) *Executor {
	if buf != nil {
		e.StdoutBuffer = buf
	} else {
		e.StdoutBuffer = &bytes.Buffer{}
	}
	return e
}

func (e *Executor) CaptureStderr(buf *bytes.Buffer) *Executor {
	if buf != nil {
		e.StderrBuffer = buf
	} else {
		e.StderrBuffer = &bytes.Buffer{}
	}
	return e
}

func (e *Executor) WithTimeout(timeout time.Duration) *Executor {
	e.timeout = timeout
	return e
}

func (e *Executor) WithMatchers(matchers ...*utils.ByteSequenceMatcher) *Executor {
	e.Matchers = make([]*utils.ByteSequenceMatcher, 0)
	e.Matchers = append(e.Matchers, matchers...)
	return e
}

func (e *Executor) WithMatchHandler(fn func(pattern string) string) *Executor {
	e.MatchHandler = fn
	return e
}

func (e *Executor) StdoutBytes() []byte {
	if e.StdoutBuffer != nil {
		return e.StdoutBuffer.Bytes()
	}
	return nil
}

func (e *Executor) StderrBytes() []byte {
	if e.StderrBuffer != nil {
		return e.StderrBuffer.Bytes()
	}
	return nil
}

func (e *Executor) SetupStreamHandlers() error {
	// stderr goes to console (commented because ssh writes only "Connection closed" messages to stderr)
	// e.Cmd.Stderr = os.Stderr
	// connect console's stdin
	// e.Cmd.Stdin = os.Stdin

	// setup stdout stream handlers
	if e.Live && e.StdoutBuffer == nil && e.StdoutHandler == nil && len(e.Matchers) == 0 {
		e.cmd.Stdout = os.Stdout
		return nil
	}

	var err error
	var stdoutReadPipe *os.File
	var stdoutHandlerWritePipe *os.File
	var stdoutHandlerReadPipe *os.File
	if e.StdoutBuffer != nil || e.StdoutHandler != nil || len(e.Matchers) > 0 {
		// create pipe for stdout
		var stdoutWritePipe *os.File
		stdoutReadPipe, stdoutWritePipe, err = os.Pipe()
		if err != nil {
			return fmt.Errorf("unable to create os pipe for stdout: %s", err)
		}

		e.cmd.Stdout = stdoutWritePipe

		e.pipesMutex.Lock()
		e.stdoutPipeFile = stdoutWritePipe
		e.stdoutReadPipe = stdoutReadPipe
		e.pipesMutex.Unlock()

		// create pipe for StdoutHandler
		if e.StdoutHandler != nil {
			stdoutHandlerReadPipe, stdoutHandlerWritePipe, err = os.Pipe()
			if err != nil {
				return fmt.Errorf("unable to create os pipe for stdoutHandler: %s", err)
			}
			e.pipesMutex.Lock()
			e.stdoutHandlerReadPipe = stdoutHandlerReadPipe
			e.pipesMutex.Unlock()
		}
	}

	var stderrReadPipe *os.File
	var stderrHandlerWritePipe *os.File
	var stderrHandlerReadPipe *os.File
	if e.StderrBuffer != nil || e.StderrHandler != nil {
		// create pipe for stderr
		var stderrWritePipe *os.File
		stderrReadPipe, stderrWritePipe, err = os.Pipe()
		if err != nil {
			return fmt.Errorf("unable to create os pipe for stderr: %s", err)
		}
		e.cmd.Stderr = stderrWritePipe

		e.pipesMutex.Lock()
		e.stderrPipeFile = stderrWritePipe
		e.stderrReadPipe = stderrReadPipe
		e.pipesMutex.Unlock()

		// create pipe for StderrHandler
		if e.StderrHandler != nil {
			stderrHandlerReadPipe, stderrHandlerWritePipe, err = os.Pipe()
			if err != nil {
				return fmt.Errorf("unable to create os pipe for stderrHandler: %s", err)
			}
			e.pipesMutex.Lock()
			e.stderrHandlerReadPipe = stderrHandlerReadPipe
			e.pipesMutex.Unlock()
		}
	}

	if e.StdinPipe {
		e.Stdin, err = e.cmd.StdinPipe()
		if err != nil {
			return fmt.Errorf("open stdin pipe: %v", err)
		}
	}

	// Start reading from stdout of a command.
	// Wait until all matchers are done and then:
	// - Copy to os.Stdout if live output is enabled
	// - Copy to buffer if capture is enabled
	// - Copy to pipe if StdoutHandler is set
	go func() {
		defer func() {
			if stdoutHandlerWritePipe != nil {
				_ = stdoutHandlerWritePipe.Close()
			}
			e.closeStdoutReadPipe()
		}()
		e.readFromStreams(stdoutReadPipe, stdoutHandlerWritePipe)
	}()

	logger := e.settings.Logger()

	go func() {
		if e.StdoutHandler == nil {
			return
		}
		defer e.closeStdoutHandlerReadPipe()
		e.ConsumeLines(stdoutHandlerReadPipe, e.StdoutHandler)
		logger.DebugContext(context.Background(), fmt.Sprintf("stop line consumer for '%s'", e.cmd.Args[0]))
	}()

	// Start reading from stderr of a command.
	// Copy to os.Stderr if live output is enabled
	// Copy to buffer if capture is enabled
	// Copy to pipe if StderrHandler is set
	go func() {
		if stderrReadPipe == nil {
			return
		}

		logger.DebugContext(context.Background(), "Start reading from stderr pipe")
		defer logger.DebugContext(context.Background(), "Stop reading from stderr pipe")

		defer func() {
			if stderrHandlerWritePipe != nil {
				_ = stderrHandlerWritePipe.Close()
			}
			e.closeStderrReadPipe()
		}()

		buf := make([]byte, 16)
		for {
			n, err := stderrReadPipe.Read(buf)

			// TODO logboek
			if e.Live {
				os.Stderr.Write(buf[:n])
			}
			if e.StderrBuffer != nil {
				e.StderrBuffer.Write(buf[:n])
			}
			if e.StderrHandler != nil {
				_, _ = stderrHandlerWritePipe.Write(buf[:n])
			}

			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
					break
				}
				logger.DebugContext(context.Background(), fmt.Sprintf("Error reading from stderr: %s\n", err))
				break
			}
		}
	}()

	go func() {
		if e.StderrHandler == nil {
			return
		}
		defer e.closeStderrHandlerReadPipe()
		e.ConsumeLines(stderrHandlerReadPipe, e.StderrHandler)
		logger.DebugContext(context.Background(), fmt.Sprintf("stop sdterr line consumer for '%s'", e.cmd.Args[0]))
	}()

	return nil
}

func (e *Executor) readFromStreams(stdoutReadPipe io.Reader, stdoutHandlerWritePipe io.Writer) {
	logger := e.settings.Logger()

	defer logger.DebugContext(context.Background(), "stop readFromStreams")

	if stdoutReadPipe == nil || reflect.ValueOf(stdoutReadPipe).IsNil() {
		return
	}

	logger.DebugContext(context.Background(), fmt.Sprintf("Start read from streams for command: %s", e.cmd.String()))

	buf := make([]byte, 16)
	var matchersDone bool
	if len(e.Matchers) == 0 {
		matchersDone = true
	}

	errorsCount := 0
	for {
		n, err := stdoutReadPipe.Read(buf)

		m := 0
		if !matchersDone {
			for _, matcher := range e.Matchers {
				m = matcher.Analyze(buf[:n])
				if matcher.IsMatched() {
					logger.DebugContext(context.Background(), fmt.Sprintf("Trigger matcher '%s'\n", matcher.Pattern))
					// matcher is triggered
					if e.MatchHandler != nil {
						res := e.MatchHandler(matcher.Pattern)
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

			// stdout for internal use, no copying to pipes until all Matchers are matched
			if !matchersDone {
				m = n
			}
		}

		if e.Live {
			os.Stdout.Write(buf[m:n])
		}
		if e.StdoutBuffer != nil {
			e.StdoutBuffer.Write(buf[m:n])
		}
		if e.StdoutHandler != nil {
			_, _ = stdoutHandlerWritePipe.Write(buf[m:n])
		}

		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
				logger.DebugContext(context.Background(), "readFromStreams: EOF")
				break
			}

			logger.DebugContext(context.Background(), fmt.Sprintf("Error reading from stdout: %s\n", err))
			errorsCount++
			if errorsCount > 1000 {
				panic(fmt.Errorf("readFromStreams: too many errors, last error %v", err))
			}
			continue
		}
	}
}

func (e *Executor) ConsumeLines(r io.Reader, fn func(l string)) {
	scanner := bufio.NewScanner(r)
	if e.StdoutSplitter != nil {
		scanner.Split(e.StdoutSplitter)
	}
	for scanner.Scan() {
		text := scanner.Text()

		if fn != nil {
			fn(text)
		}

		if text != "" {
			e.settings.Logger().DebugContext(context.Background(), fmt.Sprintf("%s: %s", e.cmd.Args[0], text))
		}
	}
}

func (e *Executor) Start() error {
	logger := e.settings.Logger()

	// setup stream handlers
	logger.DebugContext(context.Background(), fmt.Sprintf("executor: start '%s'", e.cmd.String()))
	err := e.SetupStreamHandlers()
	if err != nil {
		return err
	}

	err = e.cmd.Start()
	if err != nil {
		return err
	}

	e.ProcessWait()
	e.started.Store(true)

	logger.DebugContext(context.Background(), fmt.Sprintf("Register stoppable: '%s'", e.cmd.String()))
	e.Session.RegisterStoppable(e)

	return nil
}

func (e *Executor) ProcessWait() {
	waitErrCh := make(chan error, 1)
	e.waitCh = make(chan struct{}, 1)
	e.stopCh = make(chan struct{}, 1)
	e.doneCh = make(chan struct{})

	// wait for process in go routine
	go func() {
		waitErrCh <- e.cmd.Wait()
	}()

	go e.waitForTimeout()

	// watch for wait or stop
	go func() {
		defer func() {
			e.closeWritePipes()
			close(e.doneCh)
			close(e.waitCh)
			close(waitErrCh)
		}()
		// Wait until Stop() is called or/and Wait() is returning.
		for {
			select {
			case err := <-waitErrCh:
				if e.stop.Load() {
					// Ignore error if Stop() was called.
					// close(e.waitCh)
					e.killProcessGroup()
					return
				}
				e.setWaitError(err)
				if e.WaitHandler != nil {
					e.WaitHandler(e.waitError)
				}
				// close(e.waitCh)
				return
			case <-e.stopCh:
				// The usual e.cmd.Process.Kill() is not working for the process
				// started with the new process group (Setpgid: true).
				// Negative pid number is used to send a signal to all processes in the group.
				e.stop.Store(true)
				e.killProcessGroup()
				e.forceClosePipes()
			}
		}
	}()
}

func (e *Executor) waitForTimeout() {
	if e.timeout <= 0 {
		return
	}

	timer := time.NewTimer(e.timeout)
	defer timer.Stop()

	select {
	case <-timer.C:
		e.signalStop()
	case <-e.doneCh:
		return
	}
}

func (e *Executor) killProcessGroup() {
	err := syscall.Kill(-e.cmd.Process.Pid, syscall.SIGKILL)
	if err != nil {
		e.killError = err
	}
}

func (e *Executor) closeWritePipes() {
	logger := e.settings.Logger()

	logger.DebugContext(context.Background(), "Starting close write pipes")
	defer logger.DebugContext(context.Background(), "Stop close write pipes")

	e.pipesMutex.Lock()
	defer e.pipesMutex.Unlock()

	if e.stdoutPipeFile != nil {
		err := e.stdoutPipeFile.Close()
		if err != nil {
			logger.DebugContext(context.Background(), fmt.Sprintf("Cannot close stdout pipe: %v", err))
		}
		e.stdoutPipeFile = nil
	}

	if e.stderrPipeFile != nil {
		err := e.stderrPipeFile.Close()
		if err != nil {
			logger.DebugContext(context.Background(), fmt.Sprintf("Cannot close stderr pipe: %v", err))
		}
		e.stderrPipeFile = nil
	}
}

func (e *Executor) forceClosePipes() {
	e.closeWritePipes()

	logger := e.settings.Logger()

	logger.DebugContext(context.Background(), "Starting force close pipes")
	defer logger.DebugContext(context.Background(), "Stop force close pipes")

	e.closeStdoutReadPipe()
	e.closeStderrReadPipe()
	e.closeStdoutHandlerReadPipe()
	e.closeStderrHandlerReadPipe()
}

func (e *Executor) closeStdoutReadPipe() {
	e.closePipeFile(&e.stdoutReadPipe, "stdout read pipe")
}

func (e *Executor) closeStderrReadPipe() {
	e.closePipeFile(&e.stderrReadPipe, "stderr read pipe")
}

func (e *Executor) closeStdoutHandlerReadPipe() {
	e.closePipeFile(&e.stdoutHandlerReadPipe, "stdout handler read pipe")
}

func (e *Executor) closeStderrHandlerReadPipe() {
	e.closePipeFile(&e.stderrHandlerReadPipe, "stderr handler read pipe")
}

func (e *Executor) closePipeFile(pipe **os.File, name string) {
	e.pipesMutex.Lock()
	defer e.pipesMutex.Unlock()

	if *pipe != nil {
		err := (*pipe).Close()
		if err != nil {
			e.settings.Logger().DebugContext(context.Background(), fmt.Sprintf("Cannot close %s: %v", name, err))
		}
		*pipe = nil
	}
}

func (e *Executor) Stop() {
	logger := e.settings.Logger()

	if e.cmd == nil {
		logger.DebugContext(context.Background(), "Possible BUG: Call Executor.Stop with Cmd==nil")
		return
	}
	if !e.started.Load() {
		logger.DebugContext(context.Background(), fmt.Sprintf("Stop '%s': not started yet", e.cmd.String()))
		return
	}

	if e.stop.CompareAndSwap(false, true) {
		logger.DebugContext(context.Background(), fmt.Sprintf("Stop '%s'", e.cmd.String()))
		e.signalStop()
	} else {
		logger.DebugContext(context.Background(), fmt.Sprintf("Stop '%s': already stopping", e.cmd.String()))
	}

	e.forceClosePipes()
	<-e.waitCh
	logger.DebugContext(context.Background(), fmt.Sprintf("Stopped '%s': %d", e.cmd.String(), e.cmd.ProcessState.ExitCode()))
}

func (e *Executor) signalStop() {
	e.stopOnce.Do(func() {
		select {
		case e.stopCh <- struct{}{}:
		default:
		}
	})
}

// Run executes a command and blocks until it is finished or stopped.
func (e *Executor) Run(_ context.Context) error {
	e.settings.Logger().DebugContext(context.Background(), fmt.Sprintf("executor: run '%s'\n", e.cmd.String()))

	err := e.Start()
	if err != nil {
		return err
	}

	<-e.waitCh

	e.closeWritePipes()

	return e.WaitError()
}

func (e *Executor) Cmd() *exec.Cmd {
	return e.cmd
}

func (e *Executor) setWaitError(err error) {
	defer e.lockWaitError.Unlock()
	e.lockWaitError.Lock()
	e.waitError = err
}

func (e *Executor) WaitError() error {
	defer e.lockWaitError.RUnlock()
	e.lockWaitError.RLock()
	return e.waitError
}
