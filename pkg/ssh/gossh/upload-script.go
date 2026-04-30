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

package gossh

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"al.essio.dev/pkg/shellescape"
	gossh "github.com/deckhouse/lib-gossh"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/utils"
)

var (
	_ connection.Script = &SSHUploadScript{}
)

type SSHUploadScript struct {
	sshClient *Client

	uploadDir string

	ScriptPath string
	Args       []string
	envs       map[string]string

	sudo bool

	cleanupAfterExec bool

	stdoutHandler func(string)

	timeout time.Duration

	noLogStepOutOnError bool

	bundlerOptions []connection.BundlerOption
}

func NewSSHUploadScript(sshClient *Client, scriptPath string, args ...string) *SSHUploadScript {
	return &SSHUploadScript{
		sshClient:  sshClient,
		ScriptPath: scriptPath,
		Args:       args,

		cleanupAfterExec: true,
	}
}

func (u *SSHUploadScript) Sudo() {
	u.sudo = true
}

func (u *SSHUploadScript) WithStdoutHandler(handler func(string)) {
	u.stdoutHandler = handler
}

func (u *SSHUploadScript) WithTimeout(timeout time.Duration) {
	u.timeout = timeout
}

func (u *SSHUploadScript) WithEnvs(envs map[string]string) {
	u.envs = envs
}

func (u *SSHUploadScript) WithBundlerOpts(opts ...connection.BundlerOption) {
	u.bundlerOptions = append(make([]connection.BundlerOption, 0), opts...)
}

func (u *SSHUploadScript) WithNoLogStepOutOnError(enabled bool) {
	u.noLogStepOutOnError = enabled
}

func (u *SSHUploadScript) IsSudo() bool {
	return u.sudo
}

func (u *SSHUploadScript) UploadDir() string {
	return u.uploadDir
}

func (u *SSHUploadScript) Settings() settings.Settings {
	return u.sshClient.settings
}

// WithCleanupAfterExec option tells if ssh executor should delete uploaded script after execution was attempted or not.
// It does not care if script was executed successfully of failed.
func (u *SSHUploadScript) WithCleanupAfterExec(doCleanup bool) {
	u.cleanupAfterExec = doCleanup
}

func (u *SSHUploadScript) WithExecuteUploadDir(dir string) {
	u.uploadDir = dir
}

func (u *SSHUploadScript) Execute(ctx context.Context) ([]byte, error) {
	logger := u.sshClient.settings.Logger()

	scriptName := filepath.Base(u.ScriptPath)

	remotePath := utils.ExecuteRemoteScriptPath(u, scriptName, false)
	logger.DebugF("Uploading script %s to %s\n", u.ScriptPath, remotePath)
	err := NewSSHFile(u.sshClient.settings, u.sshClient).Upload(ctx, u.ScriptPath, remotePath)
	if err != nil {
		return nil, fmt.Errorf("upload: %v", err)
	}

	var cmd *SSHCommand
	scriptFullPath := u.pathWithEnv(utils.ExecuteRemoteScriptPath(u, scriptName, true))
	if u.sudo {
		cmd = NewSSHCommand(u.sshClient, scriptFullPath, u.Args...)
		cmd.Sudo(ctx)
	} else {
		cmd = NewSSHCommand(u.sshClient, scriptFullPath, u.Args...)
		cmd.Cmd(ctx)
	}

	if u.stdoutHandler != nil {
		cmd.WithStdoutHandler(u.stdoutHandler)
	}

	if u.timeout > 0 {
		cmd.WithTimeout(u.timeout)
	}

	err = cmd.Run(ctx)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// exitErr.Stderr is set in the "os/exec".Cmd.Output method from the Golang standard library.
			// But we call the "os/exec".Cmd.Wait method, which does not set the Stderr field.
			// We can reuse the exec.ExitError type when handling errors.
			exitErr.Stderr = cmd.StderrBytes()
		}

		err = fmt.Errorf("execute on remote: %w", err)
	}

	if u.cleanupAfterExec {
		defer func() {
			err := NewSSHCommand(u.sshClient, "rm", "-f", scriptFullPath).Run(ctx)
			if err != nil {
				logger.DebugF("Failed to delete uploaded script %s: %v", scriptFullPath, err)
			}
		}()
	}

	return cmd.StdoutBytes(), err
}

func (u *SSHUploadScript) pathWithEnv(path string) string {
	if len(u.envs) == 0 {
		return path
	}

	arrayToJoin := make([]string, 0, len(u.envs)*2)

	for k, v := range u.envs {
		vEscaped := shellescape.Quote(v)
		kvStr := fmt.Sprintf("%s=%s", k, vEscaped)
		arrayToJoin = append(arrayToJoin, kvStr)
	}

	envs := strings.Join(arrayToJoin, " ")

	return fmt.Sprintf("%s %s", envs, path)
}

func (u *SSHUploadScript) ExecuteBundle(ctx context.Context, parentDir, bundleDir string) ([]byte, error) {
	opts, err := utils.UserBundleOptsOrBashible(u.bundlerOptions...)
	if err != nil {
		return nil, err
	}

	opts = append(opts,
		utils.BundleWithNoLogStepOutOnError(u.noLogStepOutOnError),
		utils.BundleWithCommandKiller(commandKiller),
		utils.BundleWithCommandPreparator(commandPreparator),
	)

	bundler, err := utils.NewBundle(u.Settings(), u.sshClient, u.ScriptPath, u.Args, opts...)
	if err != nil {
		return nil, err
	}

	return bundler.Execute(ctx, parentDir, bundleDir)
}

func commandKiller(command connection.Command) {
	goCommand, ok := command.(*SSHCommand)
	if !ok {
		return
	}
	// Force kill bashible and close session/streams to unblock Wait/readers
	_ = goCommand.session.Signal(gossh.SIGABRT)
	if goCommand.Stdin != nil {
		_ = goCommand.Stdin.Close()
	}
	_ = goCommand.session.Close()
}

func commandPreparator(command connection.Command) {}
