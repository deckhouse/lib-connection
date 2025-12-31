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
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/deckhouse/lib-gossh/agent"

	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/clissh/cmd"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
	"github.com/deckhouse/lib-connection/pkg/ssh/utils"
)

var (
	agentInstanceSingleton sync.Once
	agentInstance          *Agent
)

// initializeNewInstance disables singleton logic
func initAgentInstance(
	sett settings.Settings,
	privateKeys []session.AgentPrivateKey,
	initializeNewInstance bool,
) (*Agent, error) {
	var err error

	if initializeNewInstance {
		inst := NewAgent(sett, &session.AgentSettings{
			PrivateKeys: privateKeys,
		})

		err = inst.Start()
		return inst, err
	}

	agentInstanceSingleton.Do(func() {
		if agentInstance == nil {
			inst := NewAgent(sett, &session.AgentSettings{
				PrivateKeys: privateKeys,
			})

			err = inst.Start()
			if err != nil {
				return
			}
			sett.RegisterOnShutdown("Stop ssh-agent", func() {
				if agentInstance != nil {
					agentInstance.Stop()
				}
			})
			agentInstance = inst
		}
	})

	if err != nil {
		// NOTICE: agentInstance will remain nil forever in the case of err, so give it another try in the next possible init-retry
		agentInstanceSingleton = sync.Once{}
	}

	return agentInstance, err
}

type Agent struct {
	sshSettings settings.Settings

	agentSettings *session.AgentSettings

	agent *cmd.SSHAgent
}

func NewAgent(sshSettings settings.Settings, agentSettings *session.AgentSettings) *Agent {
	return &Agent{
		sshSettings:   sshSettings,
		agentSettings: agentSettings,
	}
}

func (a *Agent) Start() error {
	a.agent = cmd.NewAgent(a.sshSettings, a.agentSettings)

	if len(a.agentSettings.PrivateKeys) == 0 {
		a.agent.WithAuthSock(os.Getenv("SSH_AUTH_SOCK"))
		return nil
	}

	logger := a.sshSettings.Logger()

	logger.DebugLn("agent: start ssh-agent")
	err := a.agent.Start()
	if err != nil {
		return fmt.Errorf("Start ssh-agent: %v", err)
	}

	logger.DebugLn("agent: run ssh-add for keys")
	err = a.AddKeys(a.agentSettings.PrivateKeys)
	if err != nil {
		return fmt.Errorf("Agent error: %v", err)
	}

	return nil
}

// TODO replace with x/crypto/ssh/agent ?
func (a *Agent) AddKeys(keys []session.AgentPrivateKey) error {
	err := addKeys(a.agentSettings.AuthSock, keys)
	if err != nil {
		return fmt.Errorf("Add keys: %w", err)
	}

	logger := a.sshSettings.Logger()

	if a.sshSettings.IsDebug() {
		logger.DebugLn("list added keys")
		listCmd := cmd.NewSSHAdd(a.sshSettings, a.agentSettings).ListCmd()

		output, err := listCmd.CombinedOutput()
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

func (a *Agent) Stop() {
	a.agent.Stop()
}

func addKeys(authSock string, keys []session.AgentPrivateKey) error {
	conn, err := net.Dial("unix", authSock)
	if err != nil {
		return fmt.Errorf("Error dialing with ssh agent %s: %w", authSock, err)
	}
	defer conn.Close()

	agentClient := agent.NewClient(conn)

	for _, key := range keys {
		privateKey, err := utils.GetSSHPrivateKey(key.Key, key.Passphrase)
		if err != nil {
			return err
		}

		err = agentClient.Add(agent.AddedKey{PrivateKey: privateKey})
		if err != nil {
			return fmt.Errorf("Adding ssh key with ssh agent %s: %w", authSock, err)
		}
	}

	return nil
}
