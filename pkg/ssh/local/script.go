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
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/name212/govalue"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/utils"
)

var (
	_ connection.Script = &Script{}
)

type Script struct {
	settings settings.Settings

	node              *NodeInterface
	scriptPath        string
	args              []string
	env               map[string]string
	sudo              bool
	stdoutLineHandler func(line string)
	timeout           time.Duration
	cleanupAfterRun   bool
	bundlerOptions    []connection.BundlerOption
	noOutError        bool
	// bundleDest
	// for test purposes
	bundleDest string
	// forceBundleNoSudo
	// for test purposes
	forceBundleNoSudo bool
}

func NewScript(node *NodeInterface, path string, args ...string) *Script {
	return &Script{
		node:       node,
		scriptPath: path,
		args:       args,
		settings:   node.settings,
	}
}

func (s *Script) Execute(ctx context.Context) ([]byte, error) {
	cmd := NewCommand(s.settings, s.scriptPath, s.args...)
	if s.sudo {
		cmd.Sudo(ctx)
	}

	if s.timeout > 0 {
		cmd.WithTimeout(s.timeout)
	}
	if s.env != nil {
		cmd.WithEnv(s.env)
	}
	if s.stdoutLineHandler != nil {
		cmd.WithStdoutHandler(s.stdoutLineHandler)
	}

	if s.cleanupAfterRun {
		defer os.Remove(cmd.program)
	}

	err := cmd.Run(ctx)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitErr.Stderr = cmd.StderrBytes()
		}

		return nil, fmt.Errorf("Execute locally failed: %w", err)
	}

	return cmd.StdoutBytes(), nil
}

func (s *Script) WithBundlerOpts(opts ...connection.BundlerOption) {
	s.bundlerOptions = append(make([]connection.BundlerOption, 0), opts...)
}

func (s *Script) ExecuteBundle(ctx context.Context, parentDir, bundleDir string) ([]byte, error) {
	opts, err := utils.UserBundleOptsOrBashible(s.bundlerOptions...)
	if err != nil {
		return nil, err
	}

	opts = append(opts,
		utils.BundleWithNoLogStepOutOnError(s.noOutError),
		utils.BundleWithCommandKiller(commandKiller),
		utils.BundleWithCommandPreparator(s.commandPreparator),
	)

	bundler, err := utils.NewBundle(s.settings, s.node, s.scriptPath, s.args, opts...)
	if err != nil {
		return nil, err
	}

	bundler.WithCmdProvider(s.bundleCmdProvider)

	return bundler.Execute(ctx, parentDir, bundleDir)
}

func (s *Script) Sudo() {
	s.sudo = true
}

func (s *Script) WithStdoutHandler(handler func(string)) {
	s.stdoutLineHandler = handler
}

func (s *Script) WithTimeout(timeout time.Duration) {
	s.timeout = timeout
}

func (s *Script) WithEnvs(envs map[string]string) {
	s.env = envs
}

func (s *Script) WithCleanupAfterExec(doCleanup bool) {
	s.cleanupAfterRun = doCleanup
}

func (s *Script) WithNoLogStepOutOnError(f bool) {
	s.noOutError = f
}

func (s *Script) WithBundleDest(d string) *Script {
	s.bundleDest = d
	return s
}

func (s *Script) WithForceNoSudoForBundle(f bool) *Script {
	s.forceBundleNoSudo = f
	return s
}

func (s *Script) WithExecuteUploadDir(string) {}

func (s *Script) bundleCmdProvider(ctx context.Context, node connection.Interface, parentDir, bundleDir string) (connection.Command, error) {
	fullDest := s.getBundleFullDest(bundleDir)

	srcPath := filepath.Join(parentDir, bundleDir)
	_ = os.RemoveAll(fullDest) // Cleanup from previous runs
	if err := copyRecursively(srcPath, fullDest); err != nil {
		return nil, fmt.Errorf("copy bundle to %s: %w", fullDest, err)
	}

	cmd := NewCommand(s.settings, filepath.Join(fullDest, s.scriptPath), s.args...)

	if s.timeout > 0 {
		cmd.WithTimeout(s.timeout)
	}

	if s.env != nil {
		cmd.WithEnv(s.env)
	}

	return cmd, nil
}

func (s *Script) getBundleFullDest(bundleDir string) string {
	dest := "/var/lib"
	if s.bundleDest != "" {
		dest = s.bundleDest
	}

	return filepath.Join(dest, bundleDir)
}

func (s *Script) commandPreparator(command connection.Command) {
	if !s.forceBundleNoSudo {
		return
	}

	localCmd, ok := command.(*Command)
	if !ok {
		return
	}

	localCmd.sudo = false
}

func commandKiller(command connection.Command) {
	localCmd, ok := command.(*Command)
	if !ok {
		return
	}

	cmd := localCmd.getCmd()
	if govalue.Nil(cmd) {
		return
	}

	if !govalue.Nil(cmd.ProcessState) && cmd.ProcessState.Exited() {
		return
	}

	_ = cmd.Process.Kill()
}
