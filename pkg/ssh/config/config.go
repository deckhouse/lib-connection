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

package config

type AgentPrivateKey struct {
	Key        string `json:"key"`
	Passphrase string `json:"passphrase,omitempty"`
	IsPath     bool   `json:"-"`
}

type Host struct {
	Host string `json:"host"`
}

type Mode struct {
	ForceLegacy bool `json:"legacyMode,omitempty"`
	ForceModern bool `json:"modernMode,omitempty"`
}

type Config struct {
	Mode

	User         string `json:"sshUser"`
	Port         *int   `json:"sshPort,omitempty"`
	SudoPassword string `json:"sudoPassword,omitempty"`

	PrivateKeys []AgentPrivateKey `json:"sshAgentPrivateKeys,omitempty"`

	BastionHost     string `json:"sshBastionHost,omitempty"`
	BastionPort     *int   `json:"sshBastionPort,omitempty"`
	BastionUser     string `json:"sshBastionUser,omitempty"`
	BastionPassword string `json:"sshBastionPassword,omitempty"`

	ExtraArgs string `json:"sshExtraArgs,omitempty"`
}

func (c *Config) FillDefaults() *Config {
	if c.Port == nil {
		c.Port = intPtr(DefaultPort)
	}

	if c.BastionPort == nil {
		c.BastionPort = intPtr(DefaultPort)
	}

	return c
}

func (c *Config) Clone() *Config {
	pkLen := len(c.PrivateKeys)

	var privateKeysCpy []AgentPrivateKey
	if pkLen > 0 {
		privateKeysCpy = make([]AgentPrivateKey, pkLen)
		copy(privateKeysCpy, c.PrivateKeys)
	}

	var port *int
	if c.Port != nil {
		port = intPtr(*c.Port)
	}

	var bastionPort *int
	if c.BastionPort != nil {
		bastionPort = intPtr(*c.BastionPort)
	}

	return &Config{
		Mode: c.Mode,

		User:         c.User,
		Port:         port,
		SudoPassword: c.SudoPassword,

		PrivateKeys: privateKeysCpy,

		BastionHost:     c.BastionHost,
		BastionPort:     bastionPort,
		BastionUser:     c.BastionUser,
		BastionPassword: c.BastionPassword,

		ExtraArgs: c.ExtraArgs,
	}
}

type ConnectionConfig struct {
	Config *Config
	Hosts  []Host
}
