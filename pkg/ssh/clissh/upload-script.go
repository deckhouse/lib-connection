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
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"al.essio.dev/pkg/shellescape"
	"github.com/deckhouse/lib-dhctl/pkg/log"

	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
	genssh "github.com/deckhouse/lib-connection/pkg/ssh/utils"
	"github.com/deckhouse/lib-connection/pkg/ssh/utils/tar"
)

type UploadScript struct {
	settings settings.Settings

	Session *session.Session

	uploadDir string

	ScriptPath string
	Args       []string
	envs       map[string]string

	sudo bool

	cleanupAfterExec bool

	stdoutHandler func(string)

	timeout time.Duration

	commanderMode bool
}

func NewUploadScript(sett settings.Settings, sess *session.Session, scriptPath string, args ...string) *UploadScript {
	return &UploadScript{
		Session:    sess,
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

func (u *UploadScript) WithCommanderMode(enabled bool) {
	u.commanderMode = enabled
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

func (u *UploadScript) Execute(ctx context.Context) (stdout []byte, err error) {
	scriptName := filepath.Base(u.ScriptPath)

	remotePath := genssh.ExecuteRemoteScriptPath(u, scriptName, false)
	err = NewFile(u.settings, u.Session).Upload(ctx, u.ScriptPath, remotePath)
	if err != nil {
		return nil, fmt.Errorf("upload: %v", err)
	}

	var cmd *Command
	scriptFullPath := u.pathWithEnv(genssh.ExecuteRemoteScriptPath(u, scriptName, true))
	if u.sudo {
		cmd = NewCommand(u.settings, u.Session, scriptFullPath, u.Args...)
		cmd.Sudo(ctx)
	} else {
		cmd = NewCommand(u.settings, u.Session, scriptFullPath, u.Args...)
		cmd.Cmd(ctx)
	}

	scriptCmd := cmd.CaptureStdout(nil).CaptureStderr(nil)
	if u.stdoutHandler != nil {
		scriptCmd.WithStdoutHandler(u.stdoutHandler)
	}

	if u.timeout > 0 {
		scriptCmd.WithTimeout(u.timeout)
	}

	if u.cleanupAfterExec {
		defer func() {
			err := NewCommand(u.settings, u.Session, "rm", "-f", scriptFullPath).Run(ctx)
			if err != nil {
				u.settings.Logger().DebugF("Failed to delete uploaded script %s: %v", scriptFullPath, err)
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

var ErrBashibleTimeout = errors.New("Timeout bashible step running")

func (u *UploadScript) ExecuteBundle(ctx context.Context, parentDir, bundleDir string) (stdout []byte, err error) {
	bundleName := fmt.Sprintf("bundle-%s.tar", time.Now().Format("20060102-150405"))
	bundleLocalFilepath := filepath.Join(u.settings.TmpDir(), bundleName)

	// tar cpf bundle.tar -C /tmp/dhctl.1231qd23/var/lib bashible
	err = tar.CreateTar(bundleLocalFilepath, parentDir, bundleDir)
	if err != nil {
		return nil, fmt.Errorf("tar bundle: %v", err)
	}

	u.settings.RegisterOnShutdown(
		"Delete bashible bundle folder",
		func() { _ = os.Remove(bundleLocalFilepath) },
	)

	// upload to node's deckhouse tmp directory
	err = NewFile(u.settings, u.Session).Upload(ctx, bundleLocalFilepath, u.settings.TmpDir())
	if err != nil {
		return nil, fmt.Errorf("upload: %v", err)
	}

	// sudo:
	// tar xpof ${app.DeckhouseNodeTmpPath}/bundle.tar -C /var/lib && /var/lib/bashible/bashible.sh args...
	tarCmdline := fmt.Sprintf(
		"tar xpof %s/%s -C /var/lib && /var/lib/%s/%s %s",
		u.settings.TmpDir(),
		bundleName,
		bundleDir,
		u.ScriptPath,
		strings.Join(u.Args, " "),
	)
	bundleCmd := NewCommand(u.settings, u.Session, tarCmdline)
	bundleCmd.Sudo(ctx)

	// Buffers to implement output handler logic
	lastStep := ""
	failsCounter := 0
	isBashibleTimeout := false

	processLogger := u.settings.Logger().ProcessLogger()

	handler := bundleOutputHandler(
		bundleCmd,
		u.settings.Logger(),
		processLogger,
		&lastStep,
		&failsCounter,
		&isBashibleTimeout,
		u.commanderMode,
	)
	bundleCmd.WithStdoutHandler(handler)
	bundleCmd.CaptureStdout(nil)
	bundleCmd.CaptureStderr(nil)
	err = bundleCmd.Run(ctx)
	if err != nil {
		if lastStep != "" {
			processLogger.ProcessFail()
		}

		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// exitErr.Stderr is set in the "os/exec".Cmd.Output method from the Golang standard library.
			// But we call the "os/exec".Cmd.Wait method, which does not set the Stderr field.
			// We can reuse the exec.ExitError type when handling errors.
			exitErr.Stderr = bundleCmd.StderrBytes()
		}

		err = fmt.Errorf("execute bundle: %w", err)
	} else {
		processLogger.ProcessEnd()
	}

	if isBashibleTimeout {
		return bundleCmd.StdoutBytes(), ErrBashibleTimeout
	}

	return bundleCmd.StdoutBytes(), err
}

var stepHeaderRegexp = regexp.MustCompile("^=== Step: /var/lib/bashible/bundle_steps/(.*)$")

func bundleOutputHandler(
	cmd *Command,
	logger log.Logger,
	processLogger log.ProcessLogger,
	lastStep *string,
	failsCounter *int,
	isBashibleTimeout *bool,
	commanderMode bool,
) func(string) {
	stepLogs := make([]string, 0)
	return func(l string) {
		if l == "===" {
			return
		}
		if stepHeaderRegexp.Match([]byte(l)) {
			match := stepHeaderRegexp.FindStringSubmatch(l)
			stepName := match[1]

			if *lastStep == stepName {
				logMessage := strings.Join(stepLogs, "\n")

				switch {
				case commanderMode && *failsCounter == 0:
					logger.ErrorF("%s", logMessage)
				case commanderMode && *failsCounter > 0:
					logger.ErrorF("Run step %s finished with error^^^\n", stepName)
					logger.DebugF("%s", logMessage)
				default:
					logger.ErrorF("%s", logMessage)
				}
				*failsCounter++
				stepLogs = stepLogs[:0]
				if *failsCounter > 10 {
					*isBashibleTimeout = true
					if cmd != nil {
						// Force kill bashible
						_ = cmd.cmd.Process.Kill()
					}
					return
				}

				processLogger.ProcessFail()
				stepName = fmt.Sprintf("%s, retry attempt #%d of 10\n", stepName, *failsCounter)
			} else if *lastStep != "" {
				stepLogs = make([]string, 0)
				processLogger.ProcessEnd()
				*failsCounter = 0
			}

			processLogger.ProcessStart("Run step " + stepName)
			*lastStep = match[1]
			return
		}

		stepLogs = append(stepLogs, l)
		logger.DebugLn(l)
	}
}
