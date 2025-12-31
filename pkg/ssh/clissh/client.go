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

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
	"github.com/deckhouse/lib-connection/pkg/ssh/utils"
)

func NewClient(sett settings.Settings, session *session.Session, privKeys []session.AgentPrivateKey, initNewAgent bool) *Client {
	return &Client{
		SessionSettings: session,
		privateKeys:     privKeys,
		settings:        sett,

		// We use arbitrary privKeys param, so always reinitialize agent with privKeys
		InitializeNewAgent: initNewAgent,
	}
}

type Client struct {
	settings settings.Settings

	SessionSettings *session.Session
	Agent           *Agent

	privateKeys        []session.AgentPrivateKey
	InitializeNewAgent bool

	kubeProxies []*KubeProxy
}

func (s *Client) OnlyPreparePrivateKeys() error {
	// Double start is safe here because for initializing private keys we are using sync.Once
	return s.Start()
}

func (s *Client) Start() error {
	if s.SessionSettings == nil {
		return fmt.Errorf("possible bug in ssh client: session should be created before start")
	}

	a, err := initAgentInstance(s.settings, s.privateKeys, s.InitializeNewAgent)
	if err != nil {
		return err
	}
	s.Agent = a
	s.SessionSettings.AgentSettings = s.Agent.agentSettings

	return nil
}

// Easy access to frontends

// Tunnel is used to open local (L) and remote (R) tunnels
func (s *Client) Tunnel(address string) connection.Tunnel {
	return NewTunnel(s.settings, s.SessionSettings, "L", address)
}

// ReverseTunnel is used to open remote (R) tunnel
func (s *Client) ReverseTunnel(address string) connection.ReverseTunnel {
	return NewReverseTunnel(s.settings, s.SessionSettings, address)
}

// Command is used to run commands on remote server
func (s *Client) Command(name string, arg ...string) connection.Command {
	return NewCommand(s.settings, s.SessionSettings, name, arg...)
}

// KubeProxy is used to start kubectl proxy and create a tunnel from local port to proxy port
func (s *Client) KubeProxy() connection.KubeProxy {
	p := NewKubeProxy(s.settings, s.SessionSettings)
	s.kubeProxies = append(s.kubeProxies, p)
	return p
}

// File is used to upload and download files and directories
func (s *Client) File() connection.File {
	return NewFile(s.settings, s.SessionSettings)
}

// UploadScript is used to upload script and execute it on remote server
func (s *Client) UploadScript(scriptPath string, args ...string) connection.Script {
	return NewUploadScript(s.settings, s.SessionSettings, scriptPath, args...)
}

// UploadScript is used to upload script and execute it on remote server
func (s *Client) Check() connection.Check {
	f := func(sess *session.Session, cmd string) connection.Command {
		return NewCommand(s.settings, sess, cmd)
	}
	return utils.NewCheck(f, s.SessionSettings, s.settings)
}

// Stop the client
func (s *Client) Stop() {
	// stop agent on shutdown because agent is singleton

	if s.InitializeNewAgent {
		s.Agent.Stop()
		s.Agent = nil
		s.SessionSettings.AgentSettings = nil
	}
	for _, p := range s.kubeProxies {
		p.StopAll()
	}
	s.kubeProxies = nil
}

func (s *Client) Session() *session.Session {
	return s.SessionSettings
}

func (s *Client) PrivateKeys() []session.AgentPrivateKey {
	return s.privateKeys
}

func (s *Client) RefreshPrivateKeys() error {
	return s.Agent.AddKeys(s.PrivateKeys())
}

// Loop Looping all available hosts
func (s *Client) Loop(fn connection.SSHLoopHandler) error {
	var err error

	resetSession := func() {
		s.SessionSettings = s.SessionSettings.Copy()
		s.SessionSettings.ChoiceNewHost()
	}
	defer resetSession()
	resetSession()

	for range s.SessionSettings.AvailableHosts() {
		err = fn(s)
		if err != nil {
			return err
		}
		s.SessionSettings.ChoiceNewHost()
	}

	return nil
}
