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

package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
)

const SSHAddPath = "ssh-add"

type SSHAdd struct {
	settings      settings.Settings
	AgentSettings *session.AgentSettings
}

func NewSSHAdd(sett settings.Settings, sess *session.AgentSettings) *SSHAdd {
	return &SSHAdd{settings: sett, AgentSettings: sess}
}

func (s *SSHAdd) KeyCmd(keyPath string) *exec.Cmd {
	args := []string{
		keyPath,
	}
	env := []string{
		s.AgentSettings.AuthSockEnv(),
	}
	cmd := exec.Command(SSHAddPath, args...)
	cmd.Env = append(os.Environ(), env...)
	return cmd
}

func (s *SSHAdd) ListCmd() *exec.Cmd {
	env := []string{
		s.AgentSettings.AuthSockEnv(),
	}
	cmd := exec.Command(SSHAddPath, "-l")
	cmd.Env = append(os.Environ(), env...)
	return cmd
}

func (s *SSHAdd) AddKeys(keys []string) error {
	logger := s.settings.Logger()
	for _, k := range keys {
		logger.DebugF("add key %s\n", k)
		args := []string{
			k,
		}
		env := []string{
			s.AgentSettings.AuthSockEnv(),
		}
		cmd := exec.Command(SSHAddPath, args...)
		cmd.Env = append(os.Environ(), env...)

		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("ssh-add: %s %v", string(output), err)
		}

		str := string(output)
		if str != "" && str != "\n" {
			logger.InfoF("ssh-add: %s\n", output)
		}
	}

	if s.settings.IsDebug() {
		logger.DebugLn("list added keys")
		env := []string{
			s.AgentSettings.AuthSockEnv(),
		}
		cmd := exec.Command(SSHAddPath, "-l")
		cmd.Env = append(os.Environ(), env...)

		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("ssh-add -l: %v", err)
		}

		str := string(output)
		if str != "" && str != "\n" {
			logger.InfoF("ssh-add -l: %s\n", output)
		}
	}

	return nil
}
