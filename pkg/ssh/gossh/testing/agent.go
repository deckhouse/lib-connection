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

package ssh_testing

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/log"
	"github.com/deckhouse/lib-dhctl/pkg/retry"
	"github.com/name212/govalue"
	"github.com/stretchr/testify/require"
)

type Agent struct {
	logger log.Logger

	mu       sync.RWMutex
	sockPath string
	pid      int

	stopCh chan struct{}
}

var pidRegex = regexp.MustCompile(`SSH_AGENT_PID=(\d+);`)

type PrivateKey struct {
	Path     string
	Password string
}

func StartTestAgent(t *testing.T, wrapper *TestContainerWrapper) *Agent {
	sockDir := wrapper.Settings.Test.TmpDir()
	var privateKey []PrivateKey
	if wrapper.PrivateKeyPath != "" {
		privateKey = append(privateKey, PrivateKey{
			Path: wrapper.PrivateKeyPath,
		})
	}

	agent, err := StartAgent(sockDir, wrapper.Settings.Test.Logger, privateKey...)
	// fallback to /tmp if unix socket name is too long
	if err != nil {
		if strings.Contains(err.Error(), "too long for Unix domain socket") {
			wrapper.Settings.Test.SetTmpDir("/tmp")
			sockDir = wrapper.Settings.Test.TmpDir()
			agent, err = StartAgent(sockDir, wrapper.Settings.Test.Logger, privateKey...)
		}
	}

	require.NoError(t, err)
	agent.RegisterCleanup(t)

	return agent
}

func StartAgent(sockDir string, logger log.Logger, keysPath ...PrivateKey) (*Agent, error) {
	_, err := os.Stat(sockDir)
	if err != nil {
		return nil, fmt.Errorf("failed to stat agent socket directory %s: %s", sockDir, err)
	}

	id := GenerateID("test-agent")
	sockPath := filepath.Join(sockDir, fmt.Sprintf("test-ssh-agent-%s.sock", id))

	if govalue.Nil(logger) {
		logger = TestLogger()
	}

	agent := &Agent{
		logger:   logger,
		sockPath: sockPath,
		stopCh:   make(chan struct{}, 1),
	}

	if err := agent.start(); err != nil {
		return nil, fmt.Errorf("failed to start test ssh-agent: %w", err)
	}

	for _, key := range keysPath {
		if err := agent.AddKey(key); err != nil {
			agent.Stop()
			return nil, err
		}
	}

	return agent, nil
}

func (a *Agent) start() error {
	sock := a.SockPath()
	cmd := exec.Command("ssh-agent", "-a", sock)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cannot start ssh-agent with sock %s: %w: %s", sock, err, string(out))
	}

	pidSubmatches := pidRegex.FindSubmatch(out)
	if len(pidSubmatches) < 2 {
		return fmt.Errorf("cannot find pid in ssh-agent output: %s", string(out))
	}

	pid, err := strconv.Atoi(string(pidSubmatches[1]))
	if err != nil {
		return fmt.Errorf("cannot parse pid in ssh-agent output: %s", string(out))
	}

	a.pid = pid

	a.logInfo("started successfully with pid: %d", a.Pid())

	go func() {
		stopCh := a.stopCh
		<-stopCh
		a.logInfo("shutting down ssh-agent")
		// Find the process by its PID
		process, err := os.FindProcess(a.Pid())
		if err != nil {
			a.cleanupAndLog("find process", err)
			return
		}

		err = process.Signal(syscall.SIGTERM)
		a.cleanupAndLog("kill", err)
	}()

	return nil
}

func (a *Agent) AddKey(key PrivateKey) error {
	path := key.Path
	if path == "" {
		return a.wrapError("key path is empty", fmt.Errorf("invalid input"))
	}
	_, err := os.Stat(path)
	if err != nil {
		return a.wrapError(fmt.Sprintf("failed to check private key path %s exist", path), err)
	}

	return a.run(key.Path, "ssh-add", path)
}

func (a *Agent) RemoveKey(key PrivateKey) error {
	return a.run("", "ssh-add", "-d", key.Path)
}

func (a *Agent) IsStopped() bool {
	pid := a.Pid()
	return pid == 0 || a.stopCh == nil
}

func (a *Agent) Pid() int {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return a.pid
}

func (a *Agent) SockPath() string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return a.sockPath
}

func (a *Agent) Stop() {
	if a.stopCh == nil {
		return
	}

	ch := a.stopCh
	a.stopCh = nil

	close(ch)
}

func (a *Agent) RegisterCleanup(t *testing.T) {
	t.Cleanup(func() {
		socket := a.SockPath()
		if socket == "" {
			return
		}

		a.Stop()
		leaveSocket := retry.NewEmptyParams(
			retry.WithName(fmt.Sprintf("Wait socket %s leave", socket)),
			retry.WithWait(2*time.Second),
			retry.WithAttempts(10),
			retry.WithLogger(a.logger),
		)

		_ = retry.NewLoopWithParams(leaveSocket).Run(func() error {
			_, err := os.Stat(socket)
			if err != nil {
				return nil
			}

			return fmt.Errorf("socket %s is still running", socket)
		})
	})
}

func (a *Agent) String() string {
	return fmt.Sprintf("test agent (socket: '%s'; pid: %d)", a.SockPath(), a.Pid())
}

func (a *Agent) run(stdin string, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(cmd.Env, fmt.Sprintf("SSH_AUTH_SOCK=%s", a.SockPath()))

	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}

	a.logInfo("run %s with envs: %s", cmd.String(), strings.Join(cmd.Env, " "))

	out, err := cmd.CombinedOutput()
	if err != nil {
		return a.wrapError(fmt.Sprintf("error running %s (output: %s)", cmd.String(), string(out)), err)
	}

	return nil
}

func (a *Agent) cleanupAndLog(msg string, err error) {
	if err != nil {
		a.logError("%s receive error: %v", msg, err)
		return
	}

	a.mu.Lock()

	a.pid = 0
	a.sockPath = ""

	a.mu.Unlock()

	a.logInfo("%s success", msg)
}

func (a *Agent) logInfo(f string, args ...any) {
	a.log(a.logger.InfoF, f, args...)
}

func (a *Agent) logError(f string, args ...any) {
	a.log(a.logger.ErrorF, f, args...)
}

func (a *Agent) wrapError(msg string, err error) error {
	return fmt.Errorf("%s %s: %w", msg, a.String(), err)
}

func (a *Agent) log(writeLog func(string, ...any), f string, args ...any) {
	f = a.String() + ": " + f
	writeLog(f, args...)
}
