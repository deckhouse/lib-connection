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

	"github.com/deckhouse/lib-dhctl/pkg/log"
	"github.com/stretchr/testify/require"
)

type connectionConfigAssertParams struct {
	hasErrorContains string
	err              error
	got              *ConnectionConfig
	expected         *ConnectionConfig
	logger           log.Logger
}

func assertConnectionConfig(t *testing.T, params connectionConfigAssertParams) {
	err := params.err
	cfg := params.got

	if params.hasErrorContains != "" {
		require.Error(t, err, "expected error but got none")
		// show log msg for human observability
		params.logger.ErrorF("%v", err)
		require.Contains(t, err.Error(), params.hasErrorContains, "error should contain")
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
				IsPath:     key.IsPath,
			})
		}

		cfg.Config.PrivateKeys = trimmedKeys
	}

	require.Equal(t, params.expected, cfg, "config should be equal")
}

var (
	testConfigTemplate = `
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

	testConfigTemplateEngine *template.Template
)

func generateConfigWithKeys(t *testing.T, keys []AgentPrivateKey, additionalFields string, hosts ...string) string {
	var keysMap []map[string]string
	keysJSON, err := json.Marshal(keys)
	require.NoError(t, err)
	err = json.Unmarshal(keysJSON, &keysMap)
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
	err = testConfigTemplateEngine.Execute(&tpl, map[string]any{
		"keys":   keysMap,
		"fields": additionalFields,
		"hosts":  hosts,
	})
	require.NoError(t, err, "error executing template")
	return strings.TrimRight(tpl.String(), "\n")
}

func init() {
	var err error
	testConfigTemplateEngine, err = template.New("test_connection_config").Funcs(template.FuncMap{
		"indent": func(spaces int, v string) string {
			pad := strings.Repeat(" ", spaces)
			return pad + strings.ReplaceAll(v, "\n", "\n"+pad)
		},
	}).Parse(testConfigTemplate)

	if err != nil {
		panic(err)
	}
}
