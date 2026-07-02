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

package clissh

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"al.essio.dev/pkg/shellescape"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/utils"
)

var (
	_ connection.Script = &UploadScript{}
)

type UploadScript struct {
	settings settings.Settings

	client *Client

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

func NewUploadScript(sett settings.Settings, client *Client, scriptPath string, args ...string) *UploadScript {
	return &UploadScript{
		client:     client,
		ScriptPath: scriptPath,
		Args:       args,

		settings: sett,

		cleanupAfterExec: true,
	}
}

func (u *UploadScript) Sudo() {
	u.sudo = true
}

func (u *UploadScript) WithStdoutHandler(handler func(string)) {
	u.stdoutHandler = handler
}

func (u *UploadScript) WithTimeout(timeout time.Duration) {
	u.timeout = timeout
}

func (u *UploadScript) WithEnvs(envs map[string]string) {
	u.envs = envs
}

func (u *UploadScript) WithBundlerOpts(opts ...connection.BundlerOption) {
	u.bundlerOptions = append(make([]connection.BundlerOption, 0), opts...)
}

func (u *UploadScript) WithNoLogStepOutOnError(enabled bool) {
	u.noLogStepOutOnError = enabled
}

// WithCleanupAfterExec option tells if ssh executor should delete uploaded script after execution was attempted or not.
// It does not care if script was executed successfully of failed.
func (u *UploadScript) WithCleanupAfterExec(doCleanup bool) {
	u.cleanupAfterExec = doCleanup
}

func (u *UploadScript) WithExecuteUploadDir(dir string) {
	u.uploadDir = dir
}

func (u *UploadScript) IsSudo() bool {
	return u.sudo
}

func (u *UploadScript) UploadDir() string {
	return u.uploadDir
}

func (u *UploadScript) Settings() settings.Settings {
	return u.settings
}

func (u *UploadScript) Execute(ctx context.Context) ([]byte, error) {
	scriptName := filepath.Base(u.ScriptPath)

	remotePath := utils.ExecuteRemoteScriptPath(u, scriptName, false)
	err := u.client.File().Upload(ctx, u.ScriptPath, remotePath)
	if err != nil {
		return nil, fmt.Errorf("upload: %v", err)
	}

	var genericCommand connection.Command

	scriptFullPath := u.pathWithEnv(utils.ExecuteRemoteScriptPath(u, scriptName, true))
	if u.sudo {
		genericCommand = u.client.Command(scriptFullPath, u.Args...)
		genericCommand.Sudo(ctx)
	} else {
		genericCommand = u.client.Command(scriptFullPath, u.Args...)
		genericCommand.Cmd(ctx)
	}

	cmd := genericCommand.(*Command)

	scriptCmd := cmd.CaptureStdout(nil).CaptureStderr(nil)
	if u.stdoutHandler != nil {
		scriptCmd.WithStdoutHandler(u.stdoutHandler)
	}

	if u.timeout > 0 {
		scriptCmd.WithTimeout(u.timeout)
	}

	if u.cleanupAfterExec {
		defer func() {
			err := u.client.Command("rm", "-f", scriptFullPath).Run(ctx)
			if err != nil {
				u.settings.Logger().DebugContext(ctx, fmt.Sprintf("Failed to delete uploaded script %s: %v", scriptFullPath, err))
			}
		}()
	}

	err = scriptCmd.Run(ctx)
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
	return cmd.StdoutBytes(), err
}

func (u *UploadScript) pathWithEnv(path string) string {
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

func (u *UploadScript) ExecuteBundle(ctx context.Context, parentDir, bundleDir string) ([]byte, error) {
	opts, err := utils.UserBundleOptsOrBashible(u.bundlerOptions...)
	if err != nil {
		return nil, err
	}

	opts = append(opts,
		utils.BundleWithNoLogStepOutOnError(u.noLogStepOutOnError),
		utils.BundleWithCommandKiller(commandKiller),
		utils.BundleWithCommandPreparator(commandPreparator),
	)

	bundler, err := utils.NewBundle(u.Settings(), u.client, u.ScriptPath, u.Args, opts...)
	if err != nil {
		return nil, err
	}

	return bundler.Execute(ctx, parentDir, bundleDir)
}

func commandKiller(command connection.Command) {
	cliCmd, ok := command.(*Command)
	if !ok {
		return
	}

	_ = cliCmd.cmd.Process.Kill()
}

func commandPreparator(command connection.Command) {}
