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
	"strings"
	"testing"

	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-dhctl/pkg/log"
	"github.com/stretchr/testify/require"
)

func TestParseConfig(t *testing.T) {
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
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const isDebug = true
			sett := settings.NewBaseProviders(settings.ProviderParams{
				LoggerProvider: log.SimpleLoggerProvider(
					log.NewInMemoryLoggerWithParent(
						log.NewSimpleLogger(log.LoggerOptions{IsDebug: isDebug}),
					),
				),
				IsDebug: isDebug,
			})

			cfg, err := ParseConnectionConfig(strings.NewReader(test.input), sett, test.opts...)

			if test.hasErrorContains != "" {
				require.Error(t, err, "expected error but got none")
				require.Contains(t, err.Error(), test.hasErrorContains, "error should contain")
				return
			}

			require.NoError(t, err, "expected no error but got one")
			require.Equal(t, test.expected, cfg)
		})
	}
}
