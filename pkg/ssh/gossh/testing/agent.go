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
	"strings"
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/log"
	"github.com/name212/govalue"
	"github.com/stretchr/testify/require"
)

type Agent struct {
	logger   log.Logger
	sockPath string

	pid int

	stopCh chan struct{}
}

type PrivateKey struct {
	Path     string
	Password string
}

func StartTestAgent(t *testing.T, wrapper *TestContainerWrapper) *Agent {
	sockDir := wrapper.Settings.Test.LocalTmpDir
	var privateKey []PrivateKey
	if wrapper.PrivateKeyPath != "" {
		privateKey = append(privateKey, PrivateKey{
			Path: wrapper.PrivateKeyPath,
		})
	}

	agent, err := StartAgent(sockDir, wrapper.Settings.Test.Logger, privateKey...)
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
	cmd := exec.Command("ssh-agent", "-a", a.sockPath)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("cannot start ssh-agent with sock %s: %w", a.sockPath, err)
	}

	a.pid = cmd.Process.Pid

	a.logInfo("started successfully")

	doneCh := make(chan error, 1)
	go func() {
		doneCh <- cmd.Wait()
		close(doneCh)
	}()

	go func() {
		select {
		case <-a.stopCh:
			a.logInfo("receive stop signal")
			err := cmd.Process.Kill()
			a.cleanupAndLog("kill", err)
			return
		case err := <-doneCh:
			a.cleanupAndLog("stopped external", err)
			return
		}
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
	return a.pid == 0
}

func (a *Agent) Pid() int {
	return a.pid
}

func (a *Agent) SockPath() string {
	return a.sockPath
}

func (a *Agent) Stop() {
	close(a.stopCh)
}

func (a *Agent) RegisterCleanup(t *testing.T) {
	t.Cleanup(func() {
		a.Stop()
	})
}

func (a *Agent) String() string {
	return fmt.Sprintf("test agent (socket: '%s'; pid: %d)", a.sockPath, a.pid)
}

func (a *Agent) run(stdin string, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(cmd.Env, fmt.Sprintf("SSH_AUTH_SOCK=%s", a.sockPath))

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

	a.pid = 0
	a.sockPath = ""

	a.logInfo("%s success", msg)
}

func (a *Agent) checkStopped() error {
	if a.IsStopped() {
		return a.wrapError("agent already stopped", fmt.Errorf("stopped"))
	}

	return nil
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
