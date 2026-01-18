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

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"text/template"

	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-dhctl/pkg/log"
	"github.com/stretchr/testify/require"
)

func TestParseConfig(t *testing.T) {
	configTemplate := `
apiVersion: dhctl.deckhouse.io/v1
kind: SSHConfig

{{ .fields }}

{{ if .keys }}
sshAgentPrivateKeys:
{{- range .keys }}
- key: |
{{ .key | indent 4}}
  {{- if .passphrase }}
  passphrase: "{{ .passphrase }}"
  {{- end }}
{{- end }}
{{- else }}
sshAgentPrivateKeys: []
{{- end }}
{{- range .hosts }}
---
apiVersion: dhctl.deckhouse.io/v1
kind: SSHHost
{{- if . }}
host: "{{ . }}"
{{- end }}
{{- end }}
`
	configTemplateEngine, err := template.New("test_key").Funcs(template.FuncMap{
		"indent": func(spaces int, v string) string {
			pad := strings.Repeat(" ", spaces)
			return pad + strings.Replace(v, "\n", "\n"+pad, -1)
		},
	}).Parse(configTemplate)
	require.NoError(t, err, "error parsing template")

	generateConfigWithKeys := func(t *testing.T, keys []AgentPrivateKey, additionalFields string, hosts ...string) string {
		var keysMap []map[string]string
		keysJson, err := json.Marshal(keys)
		require.NoError(t, err)
		err = json.Unmarshal(keysJson, &keysMap)
		require.NoError(t, err)

		if additionalFields == "" {
			additionalFields = `
sshPort: 22
sshUser: ubuntu
`
		}

		if len(hosts) == 0 {
			hosts = make([]string, 0)
		}

		var tpl bytes.Buffer
		err = configTemplateEngine.Execute(&tpl, map[string]any{
			"keys":   keysMap,
			"fields": additionalFields,
			"hosts":  hosts,
		})
		require.NoError(t, err, "error executing template")
		return strings.TrimRight(tpl.String(), "\n")
	}

	noRequiredHostsOpts := []ValidateOption{
		ParseWithRequiredSSHHost(false),
	}

	validPrivateKeys := []AgentPrivateKey{
		{
			Key:        generateKey(t, "no_secure_password"),
			Passphrase: "no_secure_password",
		},
		{
			Key: generateKey(t, ""),
		},
	}

	tests := []struct {
		name             string
		input            string
		hasErrorContains string
		expected         *ConnectionConfig
		opts             []ValidateOption
	}{
		{
			name:             "empty input",
			input:            "",
			hasErrorContains: `exactly one "SSHConfig" required`,
		},
		{
			name: "multiple empty documents",
			input: `
---


`,
			hasErrorContains: `exactly one "SSHConfig" required`,
		},

		{
			name: "only connection: incorrect input without auth",
			input: `
apiVersion: dhctl.deckhouse.io/v1
kind: SSHConfig
sshPort: 22
sshUser: ubuntu
`,
			hasErrorContains: "DocumentValidationFailed: Document validation failed:\n---\napiVersion: dhctl.deckhouse.io/v1\nkind: SSHConfig",
			opts:             noRequiredHostsOpts,
		},

		{
			name:             "only connection: empty keys",
			input:            generateConfigWithKeys(t, []AgentPrivateKey{}, ""),
			hasErrorContains: "* sshAgentPrivateKeys in body should have at least 1 items",
			opts:             noRequiredHostsOpts,
		},

		{
			name: "only connection: incorrect ssh key",
			input: generateConfigWithKeys(t, []AgentPrivateKey{
				{Key: "incorrect key"},
			}, ""),
			hasErrorContains: "DocumentValidationFailed: sshAgentPrivateKeys: validation rule failed: invalid ssh key: ssh: no key found",
			opts:             noRequiredHostsOpts,
		},

		{
			name: "only connection: incorrect ssh key passphrase",
			input: generateConfigWithKeys(t, []AgentPrivateKey{
				{
					Key:        generateKey(t, "no_secure_password"),
					Passphrase: "not_valid",
				},
			}, ""),
			hasErrorContains: "DocumentValidationFailed: sshAgentPrivateKeys: validation rule failed: invalid ssh key: x509: decryption password incorrect",
			opts:             noRequiredHostsOpts,
		},

		{
			name: "only connection: host document should not allow additional properties",
			input: generateConfigWithKeys(
				t,
				validPrivateKeys,
				`
sshPort: 22
sshUser: ubuntu
notAllowAdditionalProperty: "invalid"
`,
			),
			hasErrorContains: ".notAllowAdditionalProperty in body is a forbidden property",
			opts:             noRequiredHostsOpts,
		},

		{
			name: "only connection: both true legacyMode and modernMode true",
			input: `
apiVersion: dhctl.deckhouse.io/v1
kind: SSHConfig
sshPort: 22
sshUser: ubuntu
sudoPassword: "not_secure_password"
legacyMode: true
modernMode: true
`,
			hasErrorContains: "invalid ssh mode: legacyMode and modernMode both true",
			opts:             noRequiredHostsOpts,
		},

		{
			name: "only connection: correct password authentication",
			input: `
apiVersion: dhctl.deckhouse.io/v1
kind: SSHConfig
sshPort: 22
sshUser: ubuntu
sudoPassword: "not_secure_password"
`,
			hasErrorContains: "",
			opts:             noRequiredHostsOpts,
			expected: &ConnectionConfig{
				Config: &Config{
					Port:         intPtr(22),
					User:         "ubuntu",
					SudoPassword: "not_secure_password",
					BastionPort:  nil,
				},
			},
		},

		{
			name: "only connection: correct no port",
			input: `
apiVersion: dhctl.deckhouse.io/v1
kind: SSHConfig
sshUser: ubuntu
sudoPassword: "not_secure_password"
`,
			hasErrorContains: "",
			opts:             noRequiredHostsOpts,
			expected: &ConnectionConfig{
				Config: &Config{
					Port:         nil,
					User:         "ubuntu",
					SudoPassword: "not_secure_password",
					BastionPort:  nil,
				},
			},
		},

		{
			name:             "only connection: correct key authentication",
			input:            generateConfigWithKeys(t, validPrivateKeys, ""),
			hasErrorContains: "",
			opts:             noRequiredHostsOpts,
			expected: &ConnectionConfig{
				Config: &Config{
					Port:        intPtr(22),
					User:        "ubuntu",
					BastionPort: nil,
					PrivateKeys: validPrivateKeys,
				},
			},
		},

		{
			name: "only connection: correct key authentication with sudo",
			input: generateConfigWithKeys(t, validPrivateKeys, `
sshPort: 22
sshUser: ubuntu
sudoPassword: "not_secure_password"
`),
			hasErrorContains: "",
			opts:             noRequiredHostsOpts,
			expected: &ConnectionConfig{
				Config: &Config{
					Port:         intPtr(22),
					User:         "ubuntu",
					BastionPort:  nil,
					PrivateKeys:  validPrivateKeys,
					SudoPassword: "not_secure_password",
				},
			},
		},

		{
			name: "only connection: correct with bastion",
			input: generateConfigWithKeys(t, validPrivateKeys, `
sshPort: 22
sshUser: ubuntu
sudoPassword: "not_secure_password"
sshBastionHost: "127.0.0.1"
sshBastionPort: 2220
sshBastionUser: bastion
sshBastionPassword: "not_secure_password_bastion"
`),
			hasErrorContains: "",
			opts:             noRequiredHostsOpts,
			expected: &ConnectionConfig{
				Config: &Config{
					Port:            intPtr(22),
					User:            "ubuntu",
					PrivateKeys:     validPrivateKeys,
					SudoPassword:    "not_secure_password",
					BastionPort:     intPtr(2220),
					BastionUser:     "bastion",
					BastionHost:     "127.0.0.1",
					BastionPassword: "not_secure_password_bastion",
				},
			},
		},

		{
			name:             "with hosts: no hosts passed",
			input:            generateConfigWithKeys(t, validPrivateKeys, ""),
			hasErrorContains: `at least one "SSHHost" required`,
		},

		{
			name:             "with hosts: host document passed without .host key",
			input:            generateConfigWithKeys(t, validPrivateKeys, "", ""),
			hasErrorContains: ".host in body is required",
		},

		{
			name: "with hosts: host document should not allow additional properties",
			input: generateConfigWithKeys(t, validPrivateKeys, "", "127.0.0.1") + `
---
apiVersion: dhctl.deckhouse.io/v1
kind: SSHHost
host: "192.168.0.1"
notAllowAdditionalProperty: "invalid"
`,
			hasErrorContains: ".notAllowAdditionalProperty in body is a forbidden property",
		},

		{
			name: "with unknown document kind",
			input: generateConfigWithKeys(t, validPrivateKeys, "", "127.0.0.1") + `
---
apiVersion: dhctl.deckhouse.io/v1
kind: Unknown
key: key
val: 1
`,
			hasErrorContains: `Unknown kind: Unknown, dhctl.deckhouse.io/v1, expected one of ("SSHConfig", "SSHHost")`,
		},

		{
			name: "with hosts: multiple docs with same host",
			input: generateConfigWithKeys(
				t,
				validPrivateKeys,
				"",
				"127.0.0.1",
				"192.168.0.1",
				"127.0.0.1",
				"192.168.0.2",
			),
			hasErrorContains: "DocumentValidationFailed: host '127.0.0.1' present multiple times 2",
		},

		{
			name:  "with hosts: one host",
			input: generateConfigWithKeys(t, validPrivateKeys, "", "127.0.0.1"),
			expected: &ConnectionConfig{
				Config: &Config{
					Port:        intPtr(22),
					User:        "ubuntu",
					PrivateKeys: validPrivateKeys,
				},
				Hosts: []Host{
					{Host: "127.0.0.1"},
				},
			},
		},

		{
			name: "with hosts: multiple hosts",
			input: generateConfigWithKeys(
				t,
				validPrivateKeys,
				"",
				"127.0.0.1",
				"127.0.0.2",
				"192.168.0.2",
			),
			expected: &ConnectionConfig{
				Config: &Config{
					Port:        intPtr(22),
					User:        "ubuntu",
					PrivateKeys: validPrivateKeys,
				},
				Hosts: []Host{
					{Host: "127.0.0.1"},
					{Host: "127.0.0.2"},
					{Host: "192.168.0.2"},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const isDebug = true
			sett := settings.NewBaseProviders(settings.ProviderParams{
				LoggerProvider: log.SimpleLoggerProvider(
					log.NewInMemoryLoggerWithParent(
						log.NewPrettyLogger(log.LoggerOptions{IsDebug: isDebug}),
					),
				),
				IsDebug: isDebug,
			})

			cfg, err := ParseConnectionConfig(strings.NewReader(test.input), sett, test.opts...)

			if test.hasErrorContains != "" {
				require.Error(t, err, "expected error but got none")
				// show log msg for human observability
				sett.Logger().ErrorF("%v", err)
				require.Contains(t, err.Error(), test.hasErrorContains, "error should contain")
				require.Nil(t, cfg, "cfg should be nil")
				return
			}

			require.NoError(t, err, "expected no error but got one")

			if len(cfg.Config.PrivateKeys) > 0 {
				trimmedKeys := make([]AgentPrivateKey, 0, len(cfg.Config.PrivateKeys))

				for _, key := range cfg.Config.PrivateKeys {
					trimmedKeys = append(trimmedKeys, AgentPrivateKey{
						Key:        strings.TrimRight(key.Key, "\n"),
						Passphrase: key.Passphrase,
					})
				}

				cfg.Config.PrivateKeys = trimmedKeys
			}

			require.Equal(t, test.expected, cfg)
		})
	}
}
