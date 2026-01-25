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

package provider

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/name212/govalue"
	"github.com/stretchr/testify/require"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/clissh"
	sshconfig "github.com/deckhouse/lib-connection/pkg/ssh/config"
	"github.com/deckhouse/lib-connection/pkg/ssh/gossh"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
)

func TestSSHProviderClient(t *testing.T) {
	t.Run("Client", func(t *testing.T) {
		assertClientAndMultipleClientCall := func(t *testing.T, params assertParams) {
			ctx := context.TODO()

			client, err := params.provider.Client(ctx)
			assertClient(t, params, client, err)
			assertWritePrivateKeys(t, params)

			anotherClient, err := params.provider.Client(ctx)
			assertClient(t, params, anotherClient, err)
			require.True(t, client == anotherClient, "client should be the same")
			assertWritePrivateKeys(t, params)
		}

		t.Run("fill defaults", func(t *testing.T) {
			sett := testSettings(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				sett:        sett,
				bastionPort: nil,
				port:        nil,
			})

			provider := NewDefaultSSHProvider(sett, config)
			client, err := provider.Client(context.TODO())
			require.NoError(t, err, "client should created")

			sess := client.Session()
			require.NotNil(t, sess, "session should exists")

			require.Equal(t, sess.Port, "22", "should fill default port")
			require.Equal(t, sess.BastionPort, "22", "should fill default port")

			assertPrivateKeysAddedInSession(t, client, config.Config.PrivateKeys)
		})

		t.Run("private keys paths force cli-ssh no write", func(t *testing.T) {
			sett := testSettings(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				sett:        sett,
				bastionPort: intPtr(22201),
				port:        intPtr(22202),
			})

			provider := NewDefaultSSHProvider(sett, config)
			assertClientAndMultipleClientCall(t, assertParams{
				sett:               sett,
				writeKeys:          false,
				provider:           provider,
				clientType:         &clissh.Client{},
				shouldContainError: "",
				config:             config,
			})

			assertLogMessage(
				t,
				sett,
				"Use cli-ssh by default",
			)
		})

		t.Run("private keys contents force cli-ssh write one time", func(t *testing.T) {
			sett := testSettings(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyContent(t, connectionConfigParams{
				sett:        sett,
				bastionPort: intPtr(22201),
				port:        intPtr(22202),
			})

			provider := NewDefaultSSHProvider(sett, config)
			assertClientAndMultipleClientCall(t, assertParams{
				sett:               sett,
				writeKeys:          true,
				provider:           provider,
				clientType:         &clissh.Client{},
				shouldContainError: "",
				config:             config,
			})
		})

		t.Run("force cli-ssh password auth no write keys", func(t *testing.T) {
			sett := testSettings(t)
			config := defaultConnectionConfig(connectionConfigParams{
				mode: sshconfig.Mode{
					ForceLegacy: true,
				},
				sett:        sett,
				bastionPort: intPtr(22201),
				port:        intPtr(22202),
			}, nil)

			provider := NewDefaultSSHProvider(sett, config)
			assertClientAndMultipleClientCall(t, assertParams{
				sett:               sett,
				writeKeys:          false,
				provider:           provider,
				clientType:         &clissh.Client{},
				shouldContainError: "",
				config:             config,
			})

			assertLogMessage(
				t,
				sett,
				"Force cli-ssh from client settings",
			)
		})

		t.Run("password auth force go-ssh no write keys", func(t *testing.T) {
			sett := testSettings(t)
			config := defaultConnectionConfig(connectionConfigParams{
				sett:        sett,
				bastionPort: intPtr(22201),
				port:        intPtr(22202),
			}, nil)

			provider := NewDefaultSSHProvider(sett, config)
			assertClientAndMultipleClientCall(t, assertParams{
				sett:               sett,
				writeKeys:          false,
				provider:           provider,
				clientType:         &gossh.Client{},
				shouldContainError: "",
				config:             config,
			})
			assertLogMessage(
				t,
				sett,
				"Force go-ssh client because use password auth. cli-ssh does not support password auth",
			)
		})

		t.Run("force go-ssh write keys", func(t *testing.T) {
			sett := testSettings(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				mode: sshconfig.Mode{
					ForceModern: true,
				},
				sett:        sett,
				bastionPort: nil,
				port:        nil,
			})

			provider := NewDefaultSSHProvider(sett, config)
			assertClientAndMultipleClientCall(t, assertParams{
				sett:               sett,
				writeKeys:          false,
				provider:           provider,
				clientType:         &gossh.Client{},
				shouldContainError: "",
				config:             config,
			})

			assertLogMessage(
				t,
				sett,
				"Force go-ssh client from client settings",
			)
		})

		t.Run("auth methods did not provided", func(t *testing.T) {
			sett := testSettings(t)
			config := defaultConnectionConfig(connectionConfigParams{
				sett:        sett,
				bastionPort: intPtr(22201),
				port:        intPtr(22202),
			}, nil)
			config.Config.SudoPassword = ""

			provider := NewDefaultSSHProvider(sett, config)

			assertClientAndMultipleClientCall(t, assertParams{
				sett:               sett,
				writeKeys:          false,
				provider:           provider,
				shouldContainError: "Did not any auth methods provided",
				config:             config,
			})
		})

		t.Run("not exists private key passed", func(t *testing.T) {
			sett := testSettings(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				sett:        sett,
				bastionPort: intPtr(22201),
				port:        intPtr(22202),
			})

			notExistsPrivateKeyPath := filepath.Join(
				sett.TmpDir(),
				fmt.Sprintf(
					"id_rsa.no.%s",
					randString(),
				),
			)

			config.Config.PrivateKeys = append(config.Config.PrivateKeys, sshconfig.AgentPrivateKey{
				Key:    notExistsPrivateKeyPath,
				IsPath: true,
			})

			provider := NewDefaultSSHProvider(sett, config)

			expectedErr := fmt.Sprintf(
				"Cannot prepare private keys: private key %s does not exist",
				notExistsPrivateKeyPath,
			)

			assertClientAndMultipleClientCall(t, assertParams{
				sett:               sett,
				writeKeys:          false,
				provider:           provider,
				shouldContainError: expectedErr,
				config:             config,
			})
		})

		t.Run("pass dir as private key", func(t *testing.T) {
			sett := testSettings(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				sett:        sett,
				bastionPort: intPtr(22201),
				port:        intPtr(22202),
			})

			path := sett.TmpDir()

			config.Config.PrivateKeys = append(config.Config.PrivateKeys, sshconfig.AgentPrivateKey{
				Key:    path,
				IsPath: true,
			})

			provider := NewDefaultSSHProvider(sett, config)

			assertClientAndMultipleClientCall(t, assertParams{
				sett:               sett,
				writeKeys:          false,
				provider:           provider,
				shouldContainError: fmt.Sprintf("Cannot prepare private keys: path %s not regular file", path),
				config:             config,
			})
		})
	})

	t.Run("NewAdditionalClient", func(t *testing.T) {
		assertAdditionalClients := func(t *testing.T, provider *DefaultSSHProvider, additionalClients ...connection.SSHClient) {
			defaultClient, err := provider.Client(context.TODO())
			require.NoError(t, err, "default client should provided")

			clientsType := &gossh.Client{}
			require.IsType(t, clientsType, defaultClient, "default client should have valid type")

			require.Len(t, provider.additionalClients, len(additionalClients), "all additional client should stored")
			for _, client := range additionalClients {
				require.False(t, defaultClient == client, "additional client should not be default client")
				require.IsType(t, clientsType, client, "additional client should have valid type")

				defaultClientSess := defaultClient.Session()
				require.NotNil(t, defaultClientSess, "default client should have valid session")

				additionalClientSess := client.Session()
				require.NotNil(t, defaultClientSess, "additional client should have valid session")

				require.Equal(t, defaultClientSess, additionalClientSess, "additional be same as in default")

				expectedAnothers := len(provider.additionalClients) - 1
				anotherClients := make([]connection.SSHClient, 0, expectedAnothers)
				for _, cc := range provider.additionalClients {
					if cc != client {
						anotherClients = append(anotherClients, cc)
					}
				}

				require.Len(t, anotherClients, expectedAnothers, "additional clients should be different")
			}

			firstClient := additionalClients[0]
			firstClient.Session().ChoiceNewHost()
			firstClient.Session().ChoiceNewHost()

			require.NotEqual(
				t,
				defaultClient.Session(),
				firstClient.Session(),
				"change additional client session does not affect default",
			)

			for _, cc := range provider.additionalClients[1:] {
				require.NotEqual(
					t,
					cc.Session(),
					firstClient.Session(),
					"change one of additional client session does not affect another",
				)
			}
		}

		t.Run("after get default", func(t *testing.T) {
			sett := testSettings(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				mode: sshconfig.Mode{
					ForceModern: true,
				},
				sett:        sett,
				bastionPort: nil,
				port:        nil,
			})

			ctx := context.TODO()

			provider := NewDefaultSSHProvider(sett, config)
			_, err := provider.Client(ctx)
			require.NoError(t, err, "default client should provided")

			firstAdditionalClient, err := provider.NewAdditionalClient(ctx)
			require.NoError(t, err, "additional client should provided")

			secondAdditionalClient, err := provider.NewAdditionalClient(ctx)
			require.NoError(t, err, "additional client should provided")

			thirdAdditionalClient, err := provider.NewAdditionalClient(ctx)
			require.NoError(t, err, "additional client should provided")

			assertAdditionalClients(t, provider, firstAdditionalClient, secondAdditionalClient, thirdAdditionalClient)
		})

		t.Run("default client not provided", func(t *testing.T) {
			sett := testSettings(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				mode: sshconfig.Mode{
					ForceModern: true,
				},
				sett:        sett,
				bastionPort: nil,
				port:        nil,
			})

			ctx := context.TODO()

			provider := NewDefaultSSHProvider(sett, config)

			firstAdditionalClient, err := provider.NewAdditionalClient(ctx)
			require.NoError(t, err, "additional client should provided")

			require.Len(t, provider.additionalClients, 1, "additional client should stored")
			require.True(t, firstAdditionalClient == provider.additionalClients[0], "additional client should stored")

			require.True(t, govalue.Nil(provider.currentClient), "additional client should not store as default")
		})
	})

	t.Run("SwitchClient", func(t *testing.T) {
		assertSwitchClientWithGetDefault := func(t *testing.T, params assertSwitchClientParams) {
			defaultClient, err := params.provider.Client(context.TODO())
			require.NoError(t, err, "default client should provided")

			assertSwitchClient(t, params, defaultClient)
		}

		getProvider := func(sett settings.Settings, config *sshconfig.ConnectionConfig, opts ...SSHClientOption) *DefaultSSHProvider {
			provider := NewDefaultSSHProvider(sett, config)
			provider.goSSHStopWait = 3 * time.Second
			return provider
		}

		t.Run("go-ssh without additional private keys", func(t *testing.T) {
			sett := testSettings(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				mode: sshconfig.Mode{
					ForceModern: true,
				},
				sett:        sett,
				bastionPort: nil,
				port:        nil,
			})

			provider := getProvider(sett, config)

			// first switch
			assertSwitchClientWithGetDefault(t, assertSwitchClientParams{
				sett:              sett,
				provider:          provider,
				defaultConfig:     config,
				host:              "192.168.1.1",
				port:              22023,
				shouldStopDefault: true,
			})

			// second switch
			assertSwitchClientWithGetDefault(t, assertSwitchClientParams{
				sett:              sett,
				provider:          provider,
				defaultConfig:     config,
				host:              "192.168.1.2",
				port:              22024,
				shouldStopDefault: true,
			})
		})

		t.Run("go-ssh with additional private keys", func(t *testing.T) {
			sett := testSettings(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				mode: sshconfig.Mode{
					ForceModern: true,
				},
				sett:        sett,
				bastionPort: nil,
				port:        nil,
			})

			provider := getProvider(sett, config)

			params := connectionConfigParams{sett: sett}

			// first switch
			firstSwitchPrivateKeys := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, params).Config.PrivateKeys
			assertSwitchClientWithGetDefault(t, assertSwitchClientParams{
				sett:                  sett,
				provider:              provider,
				defaultConfig:         config,
				host:                  "192.168.1.1",
				port:                  22023,
				shouldStopDefault:     true,
				additionalPrivateKeys: firstSwitchPrivateKeys,
			})

			// second switch
			secondSwitchPrivateKeys := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, params).Config.PrivateKeys
			assertSwitchClientWithGetDefault(t, assertSwitchClientParams{
				sett:                  sett,
				provider:              provider,
				defaultConfig:         config,
				host:                  "192.168.1.2",
				port:                  22024,
				shouldStopDefault:     true,
				additionalPrivateKeys: secondSwitchPrivateKeys,
			})
		})

		t.Run("cli-ssh should not stop", func(t *testing.T) {
			sett := testSettings(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				mode: sshconfig.Mode{
					ForceLegacy: true,
				},
				sett:        sett,
				bastionPort: nil,
				port:        nil,
			})

			provider := getProvider(sett, config)

			params := connectionConfigParams{sett: sett}

			// first switch
			firstSwitchPrivateKeys := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, params).Config.PrivateKeys
			assertSwitchClientWithGetDefault(t, assertSwitchClientParams{
				sett:                  sett,
				provider:              provider,
				defaultConfig:         config,
				host:                  "192.168.1.1",
				port:                  22023,
				shouldStopDefault:     false,
				additionalPrivateKeys: firstSwitchPrivateKeys,
			})

			// second switch
			assertSwitchClientWithGetDefault(t, assertSwitchClientParams{
				sett:              sett,
				provider:          provider,
				defaultConfig:     config,
				host:              "192.168.1.2",
				port:              22024,
				shouldStopDefault: false,
			})
		})

		t.Run("keys with content from default should added also", func(t *testing.T) {
			sett := testSettings(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyContent(t, connectionConfigParams{
				mode: sshconfig.Mode{
					ForceLegacy: true,
				},
				sett:        sett,
				bastionPort: nil,
				port:        nil,
			})

			provider := getProvider(sett, config)

			params := connectionConfigParams{sett: sett}

			// first switch
			firstSwitchPrivateKeys := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, params).Config.PrivateKeys
			assertSwitchClientWithGetDefault(t, assertSwitchClientParams{
				sett:                  sett,
				provider:              provider,
				defaultConfig:         config,
				host:                  "192.168.1.1",
				port:                  22023,
				shouldStopDefault:     false,
				additionalPrivateKeys: firstSwitchPrivateKeys,
			})

			// second switch
			assertSwitchClientWithGetDefault(t, assertSwitchClientParams{
				sett:              sett,
				provider:          provider,
				defaultConfig:     config,
				host:              "192.168.1.2",
				port:              22024,
				shouldStopDefault: false,
			})
		})

		t.Run("switch client without default safe", func(t *testing.T) {
			sett := testSettings(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				mode: sshconfig.Mode{
					ForceLegacy: true,
				},
				sett:        sett,
				bastionPort: nil,
				port:        nil,
			})

			provider := getProvider(sett, config)

			params := connectionConfigParams{sett: sett}

			// first switch
			firstSwitchPrivateKeys := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, params).Config.PrivateKeys
			assertSwitchClient(t, assertSwitchClientParams{
				sett:                  sett,
				provider:              provider,
				defaultConfig:         config,
				host:                  "192.168.1.1",
				port:                  22023,
				shouldStopDefault:     false,
				additionalPrivateKeys: firstSwitchPrivateKeys,
			}, nil)

			assertLogMessage(
				t,
				sett,
				"CurrentClient is nil, skipping stop current client",
			)

			// second switch
			assertSwitchClientWithGetDefault(t, assertSwitchClientParams{
				sett:              sett,
				provider:          provider,
				defaultConfig:     config,
				host:              "192.168.1.2",
				port:              22024,
				shouldStopDefault: false,
			})
		})
	})

	t.Run("SwitchToDefault", func(t *testing.T) {
		type assertSwitchToDefaultParams struct {
			provider       *DefaultSSHProvider
			defaultSession *session.Session
			defaultClient  connection.SSHClient
			switchedClient connection.SSHClient
			shouldStop     bool
		}

		assertSwitchToDefault := func(t *testing.T, params assertSwitchToDefaultParams) {
			provider := params.provider
			ctx := context.TODO()

			assertClientStopped(t, params.defaultClient, params.shouldStop)

			newDefaultClient, err := provider.SwitchToDefault(ctx)
			require.NoError(t, err, "should switch to default after switch client")

			assertClientStopped(t, params.switchedClient, params.shouldStop)

			require.False(t, params.defaultClient == newDefaultClient, "default client should be different after switches")
			require.False(t, params.switchedClient == newDefaultClient, "new default client should be different after switches")
			require.Equal(t, params.defaultSession, newDefaultClient.Session(), "new default client session should be same after switches")

			afterSwitchToDefaultClient, err := provider.Client(ctx)
			require.NoError(t, err, "should get client")
			require.True(t, newDefaultClient == afterSwitchToDefaultClient, "new default client should be same after switches")

			require.Len(t, provider.additionalClients, 0, "should not add to additional clients")
		}

		assertSwitchToDefaultViaSwitchToNew := func(t *testing.T, sett settings.Settings, config *sshconfig.ConnectionConfig, shouldStop bool) {
			provider := NewDefaultSSHProvider(sett, config)
			provider.goSSHStopWait = 3 * time.Second
			ctx := context.TODO()

			defaultClient, err := provider.Client(ctx)
			require.NoError(t, err, "default client should be created")

			defaultClientSession := defaultClient.Session()

			switchedClient := assertSwitchClient(t, assertSwitchClientParams{
				sett:              sett,
				provider:          provider,
				defaultConfig:     config,
				host:              "192.168.1.2",
				port:              22024,
				shouldStopDefault: shouldStop,
			}, defaultClient)

			assertSwitchToDefault(t, assertSwitchToDefaultParams{
				provider:       provider,
				defaultSession: defaultClientSession,
				defaultClient:  defaultClient,
				switchedClient: switchedClient,
				shouldStop:     shouldStop,
			})
		}

		t.Run("switch to default after switch to new client", func(t *testing.T) {
			t.Run("go-ssh should stop clients", func(t *testing.T) {
				sett := testSettings(t)
				config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
					mode: sshconfig.Mode{
						ForceModern: true,
					},
					sett:        sett,
					bastionPort: nil,
					port:        nil,
				})

				assertSwitchToDefaultViaSwitchToNew(t, sett, config, true)
			})

			t.Run("cli-ssh should not stop clients", func(t *testing.T) {
				sett := testSettings(t)
				config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
					mode: sshconfig.Mode{
						ForceLegacy: true,
					},
					sett:        sett,
					bastionPort: nil,
					port:        nil,
				})

				assertSwitchToDefaultViaSwitchToNew(t, sett, config, false)
			})
		})

		t.Run("switch to default safe without get default before", func(t *testing.T) {
			sett := testSettings(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				mode: sshconfig.Mode{
					ForceLegacy: true,
				},
				sett:        sett,
				bastionPort: nil,
				port:        nil,
			})

			provider := NewDefaultSSHProvider(sett, config)
			ctx := context.TODO()

			client, err := provider.SwitchToDefault(ctx)
			assertClient(t, assertParams{
				sett:               sett,
				writeKeys:          false,
				provider:           provider,
				clientType:         &clissh.Client{},
				shouldContainError: "",
				config:             config,
			}, client, err)

			defaultClient, err := provider.Client(ctx)
			require.NoError(t, err, "should get client")
			require.True(t, defaultClient == client, "switch to default client should set current")

			require.Len(t, provider.additionalClients, 0, "should not store additional client")
		})
	})
}

type assertSwitchClientParams struct {
	sett                  settings.Settings
	provider              *DefaultSSHProvider
	defaultConfig         *sshconfig.ConnectionConfig
	host                  string
	port                  int
	shouldStopDefault     bool
	additionalPrivateKeys []sshconfig.AgentPrivateKey
}

func assertClientStopped(t *testing.T, client connection.SSHClient, shouldStop bool) {
	assertStopped := require.False
	if shouldStop {
		assertStopped = require.True
	}

	assertStopped(t, client.IsStopped(), "default client stopped check failed")
}

func assertSwitchClient(t *testing.T, params assertSwitchClientParams, defaultClient connection.SSHClient) connection.SSHClient {
	switchClientSession := defaultSession(params.host, params.port)
	var privateKeys []session.AgentPrivateKey
	for _, key := range params.additionalPrivateKeys {
		privateKeys = append(privateKeys, session.AgentPrivateKey{
			Key:        key.Key,
			Passphrase: key.Passphrase,
		})
	}

	provider := params.provider
	ctx := context.TODO()

	switchedClient, err := provider.SwitchClient(ctx, switchClientSession, privateKeys)

	require.NoError(t, err, "should provide client")

	if !govalue.Nil(defaultClient) {
		require.False(t, defaultClient == switchedClient, "should return a new client")
		assertClientStopped(t, defaultClient, params.shouldStopDefault)
	}

	expectedKeysInSession := append(make([]sshconfig.AgentPrivateKey, 0), params.additionalPrivateKeys...)
	expectedKeysInSession = append(expectedKeysInSession, params.defaultConfig.Config.PrivateKeys...)
	assertPrivateKeysAddedInSession(t, switchedClient, expectedKeysInSession)
	require.Equal(t, switchClientSession, switchedClient.Session(), "should set correct session")

	defaultClientAfterSwitch, err := provider.Client(ctx)
	require.NoError(t, err, "should provide client")
	require.True(t, defaultClientAfterSwitch == switchedClient, "switch client should stored as default new client")

	require.Len(t, provider.additionalClients, 0, "should not store additional client")

	return switchedClient
}

type connectionConfigParams struct {
	sett        settings.Settings
	mode        sshconfig.Mode
	bastionPort *int
	port        *int
}

func writePrivateKey(t *testing.T, params connectionConfigParams, password string) string {
	require.False(t, govalue.Nil(params.sett), "settings should be passed")

	tmpDir := params.sett.TmpDir()

	key := generateKey(t, password)

	name := "pre-created-no-pass.id.rsa"
	if password != "" {
		name = "pre-created-pass.id.rsa"
	}

	id := GenerateID(name)
	path := filepath.Join(tmpDir, fmt.Sprintf("%s.%s", name, id))

	err := os.WriteFile(path, []byte(key), 0600)
	require.NoError(t, err, "private key should have been created")

	return path
}

func testCreateSSHConnectionConfigWithPrivateKeyPaths(t *testing.T, params connectionConfigParams) *sshconfig.ConnectionConfig {
	keyWithoutPasswordPath := writePrivateKey(t, params, "")
	password := RandPassword(12)
	keyWithPasswordPath := writePrivateKey(t, params, password)

	return defaultConnectionConfig(params, []sshconfig.AgentPrivateKey{
		{
			Key:    keyWithoutPasswordPath,
			IsPath: true,
		},

		{
			Key:        keyWithPasswordPath,
			Passphrase: password,
			IsPath:     true,
		},
	})
}

func testCreateSSHConnectionConfigWithPrivateKeyContent(t *testing.T, params connectionConfigParams) *sshconfig.ConnectionConfig {
	keyWithoutPassword := generateKey(t, "")
	password := RandPassword(12)
	keyWithPassword := generateKey(t, password)

	return defaultConnectionConfig(params, []sshconfig.AgentPrivateKey{
		{
			Key:    keyWithoutPassword,
			IsPath: false,
		},

		{
			Key:        keyWithPassword,
			Passphrase: password,
			IsPath:     false,
		},
	})
}

func defaultConnectionConfig(params connectionConfigParams, keys []sshconfig.AgentPrivateKey) *sshconfig.ConnectionConfig {
	return &sshconfig.ConnectionConfig{
		Config: &sshconfig.Config{
			Mode: params.mode,

			User: "user",
			Port: params.port,

			SudoPassword: "not secure",

			PrivateKeys: keys,

			BastionHost:     "127.0.0.1",
			BastionPort:     params.bastionPort,
			BastionUser:     "bastion",
			BastionPassword: "not secure bastion",
		},

		Hosts: []sshconfig.Host{
			{
				Host: "192.168.0.1",
			},

			{
				Host: "192.168.0.2",
			},

			{
				Host: "192.168.0.3",
			},
		},
	}
}

func assertPrivateKeysAddedInSession(t *testing.T, client connection.SSHClient, expectedKeys []sshconfig.AgentPrivateKey) {
	clientPrivateKeys := client.PrivateKeys()

	keysPaths := make(map[string]session.AgentPrivateKey, len(clientPrivateKeys))
	for _, key := range clientPrivateKeys {
		keysPaths[key.Key] = key
	}

	require.Len(t, keysPaths, len(expectedKeys))

	type keyWithContent struct {
		sessionKey  session.AgentPrivateKey
		expectedKey sshconfig.AgentPrivateKey
	}

	keysWithContent := make([]keyWithContent, 0)

	for i, key := range expectedKeys {
		if key.IsPath {
			require.Contains(t, keysPaths, key.Key, "should have private key path")
			require.Equal(t, keysPaths[key.Key].Passphrase, key.Passphrase, "should correct passphrase")
			continue
		}

		keysWithContent = append(keysWithContent, keyWithContent{
			sessionKey:  clientPrivateKeys[i],
			expectedKey: key,
		})
	}

	for _, k := range keysWithContent {
		path := k.sessionKey.Key
		content, err := os.ReadFile(path)
		require.NoError(t, err, "error reading file %s", path)
		require.Equal(
			t,
			strings.TrimSpace(k.expectedKey.Key),
			strings.TrimSpace(string(content)),
			"file content mismatch for %s", path,
		)
		require.Equal(t, k.sessionKey.Passphrase, k.expectedKey.Passphrase, "should correct passphrase")
	}
}

type assertParams struct {
	sett               settings.Settings
	writeKeys          bool
	provider           *DefaultSSHProvider
	clientType         connection.SSHClient
	shouldContainError string
	config             *sshconfig.ConnectionConfig
}

func assertClient(t *testing.T, params assertParams, client connection.SSHClient, err error) {
	if params.shouldContainError != "" {
		require.Error(t, err, "client should not created")
		require.Contains(t, err.Error(), params.shouldContainError, "should contain error")
		require.True(t, govalue.Nil(client), "client should not created")
		return
	}

	require.NoError(t, err, "client should created")
	require.False(t, govalue.Nil(client), "client should have been created")
	require.IsType(t, params.clientType, client, "client should have valid type")

	config := params.config.Config.Clone().FillDefaults()
	clientSession := client.Session()

	sessionHosts := make(map[string]struct{})
	for _, host := range clientSession.AvailableHosts() {
		sessionHosts[host.Host] = struct{}{}
	}
	require.Len(t, sessionHosts, len(params.config.Hosts), "should have all hosts")
	for _, host := range params.config.Hosts {
		require.Contains(t, sessionHosts, host.Host, "host should be present in session %s", host.Host)
	}

	assertPrivateKeysAddedInSession(t, client, params.config.Config.PrivateKeys)

	require.Equal(t, config.PortString(), clientSession.Port, "port should be correctly")
	require.Equal(t, config.SudoPassword, clientSession.BecomePass, "sudo password correctly")
	require.Equal(t, config.User, clientSession.User, "user should be correct")

	require.Equal(t, config.BastionPassword, clientSession.BastionPassword, "bastion password correctly")
	require.Equal(t, config.BastionUser, clientSession.BastionUser, "bastion user password correctly")
	require.Equal(t, config.BastionPortString(), clientSession.BastionPort, "bastion port should be correctly")
	require.Equal(t, config.BastionHost, clientSession.BastionHost, "bastion port should be correctly")

	require.Equal(t, config.ExtraArgs, clientSession.ExtraArgs, "extra args should be correct")
}

var privateKeyPattern = regexp.MustCompile(`^pk\.[0-9]+$`)

func assertWritePrivateKeys(t *testing.T, params assertParams) {
	const rootSubDir = "lib-connection-ssh"
	rootDir := filepath.Join(params.sett.TmpDir(), rootSubDir)

	if !params.writeKeys {
		_, err := os.Stat(rootDir)
		require.Error(t, err, "root dir should not exist")
		require.ErrorIs(t, err, os.ErrNotExist, "root dir should not exist")
		return
	}

	subDirs := make([]string, 0, 1)
	keys := make([]string, 0, 2)

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() && info.Name() != rootSubDir {
			subDirs = append(subDirs, path)
			return nil
		}

		if privateKeyPattern.MatchString(info.Name()) {
			keys = append(keys, path)
		}

		return nil
	})

	require.NoError(t, err, "failed to walk directory")

	expectedKeysCount := 0
	for _, key := range params.config.Config.PrivateKeys {
		if !key.IsPath {
			expectedKeysCount++
		}
	}

	require.Len(
		t,
		subDirs,
		1,
		"should contain one sub directory for private keys got subdirs: %v", subDirs,
	)
	require.Len(
		t,
		keys,
		expectedKeysCount,
		"should contain all keys to write got keys: %v", keys,
	)
}

func defaultSession(host string, port int) *session.Session {
	return session.NewSession(session.Input{
		User:       "user",
		Port:       fmt.Sprintf("%d", port),
		BecomePass: RandPassword(12),
		AvailableHosts: []session.Host{
			{
				Host: host,
				Name: host,
			},
		},
	})
}

func intPtr(i int) *int {
	return &i
}
