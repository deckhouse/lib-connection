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
}

type Host struct {
	Host string `json:"host"`
}

type Config struct {
	User            string            `json:"user"`
	Port            *int32            `json:"port,omitempty"`
	PrivateKeys     []AgentPrivateKey `json:"privateKeys,omitempty"`
	ExtraArgs       string            `json:"extraArgs,omitempty"`
	BastionHost     string            `json:"bastionHost,omitempty"`
	BastionPort     *int32            `json:"bastionPort,omitempty"`
	BastionUser     string            `json:"bastionUser,omitempty"`
	BastionPassword string            `json:"bastionPassword,omitempty"`
	SudoPassword    string            `json:"sudoPassword,omitempty"`
	LegacyMode      bool              `json:"legacyMode,omitempty"`
	ModernMode      bool              `json:"modernMode,omitempty"`
}

type ConnectionConfig struct {
	Config *Config
	Hosts  []Host
}
