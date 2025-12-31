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
	"github.com/deckhouse/lib-connection/pkg/tests"
)

func TestSSHProviderClient(t *testing.T) {
	t.Run("Client", func(t *testing.T) {
		assertClientAndMultipleClientCall := func(t *testing.T, params assertParams) {
			ctx := context.TODO()

			client, err := params.provider.Client(ctx)
			assertClient(t, params, client, err)
			assertWritePrivateKeys(t, params)

			params.assertPrivateKeysPrepared(t)

			anotherClient, err := params.provider.Client(ctx)
			assertClient(t, params, anotherClient, err)
			require.True(t, client == anotherClient, "client should be the same")
			assertWritePrivateKeys(t, params)

			params.assertPrivateKeysPrepared(t)
		}

		t.Run("fill defaults", func(t *testing.T) {
			test := newTest(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				test:        test,
				bastionPort: nil,
				port:        nil,
			})

			provider := newTestProvider(test.Settings(), config)
			client, err := provider.Client(context.TODO())
			require.NoError(t, err, "client should created")

			sess := client.Session()
			require.NotNil(t, sess, "session should exists")

			require.Equal(t, sess.Port, "22", "should fill default port")
			require.Equal(t, sess.BastionPort, "22", "should fill default port")

			assertPrivateKeysAddedInSession(t, client, config.Config.PrivateKeys)
		})

		t.Run("private keys paths force cli-ssh no write", func(t *testing.T) {
			test := newTest(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				test:        test,
				bastionPort: tests.Ptr(22201),
				port:        tests.Ptr(22202),
			})

			sett := test.Settings()
			provider := newTestProvider(sett, config)
			assertClientAndMultipleClientCall(t, assertParams{
				sett:                      sett,
				writeKeys:                 false,
				provider:                  provider,
				clientType:                &clissh.Client{},
				shouldContainError:        "",
				config:                    config,
				privateKeysShouldPrepared: true,
			})

			tests.AssertLogMessage(
				t,
				sett,
				"Use cli-ssh by default",
			)
		})

		t.Run("private keys contents force cli-ssh write one time", func(t *testing.T) {
			test := newTest(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyContent(t, connectionConfigParams{
				test:        test,
				bastionPort: tests.Ptr(22201),
				port:        tests.Ptr(22202),
			})

			sett := test.Settings()
			provider := newTestProvider(sett, config)
			assertClientAndMultipleClientCall(t, assertParams{
				sett:                      sett,
				writeKeys:                 true,
				provider:                  provider,
				clientType:                &clissh.Client{},
				shouldContainError:        "",
				config:                    config,
				privateKeysShouldPrepared: true,
			})
		})

		t.Run("force cli-ssh password auth no write keys", func(t *testing.T) {
			test := newTest(t)
			config := defaultConnectionConfig(connectionConfigParams{
				mode: sshconfig.Mode{
					ForceLegacy: true,
				},
				test:        test,
				bastionPort: tests.Ptr(22201),
				port:        tests.Ptr(22202),
			}, nil)

			sett := test.Settings()
			provider := newTestProvider(sett, config)
			assertClientAndMultipleClientCall(t, assertParams{
				sett:                      sett,
				writeKeys:                 false,
				provider:                  provider,
				clientType:                &clissh.Client{},
				shouldContainError:        "",
				config:                    config,
				privateKeysShouldPrepared: true,
			})

			tests.AssertLogMessage(
				t,
				sett,
				"Force cli-ssh from client settings",
			)
		})

		t.Run("password auth force go-ssh no write keys", func(t *testing.T) {
			test := newTest(t)
			config := defaultConnectionConfig(connectionConfigParams{
				test:        test,
				bastionPort: tests.Ptr(22201),
				port:        tests.Ptr(22202),
			}, nil)

			sett := test.Settings()
			provider := newTestProvider(sett, config)
			assertClientAndMultipleClientCall(t, assertParams{
				sett:                      sett,
				writeKeys:                 false,
				provider:                  provider,
				clientType:                &gossh.Client{},
				shouldContainError:        "",
				config:                    config,
				privateKeysShouldPrepared: true,
			})
			tests.AssertLogMessage(
				t,
				sett,
				"Force go-ssh client because use password auth. cli-ssh does not support password auth",
			)
		})

		t.Run("force go-ssh write keys", func(t *testing.T) {
			test := newTest(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				mode: sshconfig.Mode{
					ForceModern: true,
				},
				test:        test,
				bastionPort: nil,
				port:        nil,
			})

			sett := test.Settings()
			provider := newTestProvider(sett, config)

			assertClientAndMultipleClientCall(t, assertParams{
				sett:                      sett,
				writeKeys:                 false,
				provider:                  provider,
				clientType:                &gossh.Client{},
				shouldContainError:        "",
				config:                    config,
				privateKeysShouldPrepared: true,
			})

			tests.AssertLogMessage(
				t,
				sett,
				"Force go-ssh client from client settings",
			)
		})

		t.Run("auth methods did not provided", func(t *testing.T) {
			test := newTest(t)
			config := defaultConnectionConfig(connectionConfigParams{
				test:        test,
				bastionPort: tests.Ptr(22201),
				port:        tests.Ptr(22202),
			}, nil)
			config.Config.SudoPassword = ""

			sett := test.Settings()
			provider := newTestProvider(sett, config)

			assertClientAndMultipleClientCall(t, assertParams{
				sett:               sett,
				writeKeys:          false,
				provider:           provider,
				shouldContainError: "Did not any auth methods provided",
				config:             config,
			})
		})

		t.Run("not exists private key passed", func(t *testing.T) {
			test := newTest(t)
			sett := test.Settings()
			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				test:        test,
				bastionPort: tests.Ptr(22201),
				port:        tests.Ptr(22202),
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

			provider := newTestProvider(sett, config)

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
			test := newTest(t)
			sett := test.Settings()

			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				test:        test,
				bastionPort: tests.Ptr(22201),
				port:        tests.Ptr(22202),
			})

			path := sett.TmpDir()

			config.Config.PrivateKeys = append(config.Config.PrivateKeys, sshconfig.AgentPrivateKey{
				Key:    path,
				IsPath: true,
			})

			provider := newTestProvider(test.Settings(), config)

			assertClientAndMultipleClientCall(t, assertParams{
				sett:               sett,
				writeKeys:          false,
				provider:           provider,
				shouldContainError: fmt.Sprintf("Cannot prepare private keys: path %s not regular file", path),
				config:             config,
			})
		})
	})

	t.Run("SwitchClient", func(t *testing.T) {
		assertSwitchClientWithGetDefault := func(t *testing.T, params assertSwitchClientParams) {
			defaultClient, err := params.provider.Client(context.TODO())
			require.NoError(t, err, "default client should provided")

			assertSwitchClient(t, params, defaultClient)
		}

		t.Run("go-ssh without additional private keys", func(t *testing.T) {
			test := newTest(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				mode: sshconfig.Mode{
					ForceModern: true,
				},
				test:        test,
				bastionPort: nil,
				port:        nil,
			})

			sett := test.Settings()
			provider := newTestProvider(sett, config)

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
			test := newTest(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				mode: sshconfig.Mode{
					ForceModern: true,
				},
				test:        test,
				bastionPort: nil,
				port:        nil,
			})

			sett := test.Settings()
			provider := newTestProvider(sett, config)

			params := connectionConfigParams{test: test}

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
			test := newTest(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				mode: sshconfig.Mode{
					ForceLegacy: true,
				},
				test:        test,
				bastionPort: nil,
				port:        nil,
			})

			sett := test.Settings()
			provider := newTestProvider(sett, config)

			params := connectionConfigParams{test: test}

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
			test := newTest(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyContent(t, connectionConfigParams{
				mode: sshconfig.Mode{
					ForceLegacy: true,
				},
				test:        test,
				bastionPort: nil,
				port:        nil,
			})

			sett := test.Settings()
			provider := newTestProvider(sett, config)

			params := connectionConfigParams{test: test}

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
			test := newTest(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				mode: sshconfig.Mode{
					ForceLegacy: true,
				},
				test:        test,
				bastionPort: nil,
				port:        nil,
			})

			sett := test.Settings()
			provider := newTestProvider(sett, config)

			params := connectionConfigParams{test: test}

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

			tests.AssertLogMessage(
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
			provider := newTestProvider(sett, config)

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
				test := newTest(t)
				config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
					mode: sshconfig.Mode{
						ForceModern: true,
					},
					test:        test,
					bastionPort: nil,
					port:        nil,
				})

				assertSwitchToDefaultViaSwitchToNew(t, test.Settings(), config, true)
			})

			t.Run("cli-ssh should not stop clients", func(t *testing.T) {
				test := newTest(t)
				config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
					mode: sshconfig.Mode{
						ForceLegacy: true,
					},
					test:        test,
					bastionPort: nil,
					port:        nil,
				})

				assertSwitchToDefaultViaSwitchToNew(t, test.Settings(), config, false)
			})
		})

		t.Run("switch to default safe without get default before", func(t *testing.T) {
			test := newTest(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				mode: sshconfig.Mode{
					ForceLegacy: true,
				},
				test:        test,
				bastionPort: tests.Ptr(22202),
				port:        tests.Ptr(22203),
			})

			provider := newTestProvider(test.Settings(), config)
			ctx := context.TODO()

			client, err := provider.SwitchToDefault(ctx)
			assertClient(t, assertParams{
				sett:               test.Settings(),
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

	t.Run("NewAdditionalClient", func(t *testing.T) {
		type assertAdditionalClientsParams struct {
			defaultClient             connection.SSHClient
			clientsType               connection.SSHClient
			gotAdditionalClients      []connection.SSHClient
			additionalClientsForCheck []connection.SSHClient

			expectedSession *session.Session
		}

		assertAdditionalClients := func(t *testing.T, params assertAdditionalClientsParams) {
			defaultClient := params.defaultClient
			additionalClients := params.gotAdditionalClients
			forCheck := params.additionalClientsForCheck
			clientsType := params.clientsType

			require.IsType(t, clientsType, defaultClient, "default client should have valid type")

			defaultClientPrivateKeys := defaultClient.PrivateKeys()

			require.Len(t, forCheck, len(additionalClients), "all additional client should stored")
			for _, client := range additionalClients {
				require.False(t, defaultClient == client, "additional client should not be default client")
				require.IsType(t, clientsType, client, "additional client should have valid type")

				additionalClientSess := client.Session()
				require.NotNil(t, additionalClientSess, "additional client should have valid session")

				require.Equal(t, params.expectedSession, additionalClientSess, "additional be with valid session")
				require.Equal(t, defaultClientPrivateKeys, client.PrivateKeys(), "additional client should have private keys")

				expectedAnothers := len(forCheck) - 1
				anotherClients := make([]connection.SSHClient, 0, expectedAnothers)
				for _, cc := range forCheck {
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

			for _, cc := range forCheck[1:] {
				require.NotEqual(
					t,
					cc.Session(),
					firstClient.Session(),
					"change one of additional client session does not affect another",
				)
			}
		}

		assertAdditionalClientsWithDefault := func(t *testing.T, provider *DefaultSSHProvider, additionalClients ...connection.SSHClient) {
			defaultClient, err := provider.Client(context.TODO())
			require.NoError(t, err, "default client should provided")

			defaultClientSess := defaultClient.Session()
			require.NotNil(t, defaultClientSess, "default client should have valid session")

			assertAdditionalClients(t, assertAdditionalClientsParams{
				defaultClient:             defaultClient,
				clientsType:               &clissh.Client{},
				gotAdditionalClients:      append([]connection.SSHClient{}, additionalClients...),
				additionalClientsForCheck: provider.additionalClients,
				expectedSession:           defaultClientSess,
			})
		}

		t.Run("after get default", func(t *testing.T) {
			test := newTest(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				mode: sshconfig.Mode{
					ForceLegacy: true,
				},
				test:        test,
				bastionPort: nil,
				port:        nil,
			})

			ctx := context.TODO()

			provider := newTestProvider(test.Settings(), config)
			_, err := provider.Client(ctx)
			require.NoError(t, err, "default client should provided")

			firstAdditionalClient, err := provider.NewAdditionalClient(ctx)
			require.NoError(t, err, "additional client should provided")

			secondAdditionalClient, err := provider.NewAdditionalClient(ctx)
			require.NoError(t, err, "additional client should provided")

			thirdAdditionalClient, err := provider.NewAdditionalClient(ctx)
			require.NoError(t, err, "additional client should provided")

			assertAdditionalClientsWithDefault(t, provider, firstAdditionalClient, secondAdditionalClient, thirdAdditionalClient)
		})

		t.Run("default client not provided", func(t *testing.T) {
			test := newTest(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				mode: sshconfig.Mode{
					ForceLegacy: true,
				},
				test:        test,
				bastionPort: nil,
				port:        nil,
			})

			ctx := context.TODO()

			provider := newTestProvider(test.Settings(), config)

			firstAdditionalClient, err := provider.NewAdditionalClient(ctx)
			require.NoError(t, err, "additional client should provided")

			require.Len(t, provider.additionalClients, 1, "additional client should stored")
			require.True(t, firstAdditionalClient == provider.additionalClients[0], "additional client should stored")

			require.True(t, govalue.Nil(provider.currentClient), "additional client should not store as default")
		})

		t.Run("after switches", func(t *testing.T) {
			test := newTest(t)
			defaultConfig := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				mode: sshconfig.Mode{
					ForceLegacy: true,
				},
				test:        test,
				bastionPort: nil,
				port:        nil,
			})

			ctx := context.TODO()
			sett := test.Settings()

			provider := newTestProvider(sett, defaultConfig)

			defaultClient, err := provider.Client(ctx)
			require.NoError(t, err, "default client should provided")

			firstAdditionalClient, err := provider.NewAdditionalClient(ctx)
			require.NoError(t, err, "additional client should provided")

			secondAdditionalClient, err := provider.NewAdditionalClient(ctx)
			require.NoError(t, err, "additional client should provided")

			assertAdditionalClientsWithDefault(t, provider, firstAdditionalClient, secondAdditionalClient)

			// switch to new
			switchConfig := testCreateSSHConnectionConfigWithPrivateKeyContent(t, connectionConfigParams{
				test:        test,
				bastionPort: tests.Ptr(23066),
				port:        tests.Ptr(23067),
			}).Config

			switchSession := session.NewSession(session.Input{
				User:       "another",
				Port:       switchConfig.PortString(),
				BecomePass: tests.RandPassword(10),

				BastionHost:     "127.0.1.1",
				BastionPort:     switchConfig.BastionPortString(),
				BastionUser:     "bastion",
				BastionPassword: tests.RandPassword(10),

				AvailableHosts: []session.Host{
					{
						Host: "192.168.100.1",
						Name: "192.168.100.1",
					},
					{
						Host: "192.168.100.2",
						Name: "192.168.100.2",
					},
					{
						Host: "192.168.100.3",
						Name: "192.168.100.3",
					},
				},
			})

			privateKeys := make([]session.AgentPrivateKey, 0, len(switchConfig.PrivateKeys))
			for _, key := range switchConfig.PrivateKeys {
				privateKeys = append(privateKeys, session.AgentPrivateKey{
					Key:        key.Key,
					Passphrase: key.Passphrase,
				})
			}

			_, err = provider.SwitchClient(ctx, switchSession, privateKeys)
			require.NoError(t, err, "should switch")

			defaultClientAfterSwitch, err := provider.Client(ctx)
			require.NoError(t, err, "default client should provided")

			firstAdditionalClientAfterSwitch, err := provider.NewAdditionalClient(ctx)
			require.NoError(t, err, "additional client should provided")

			secondAdditionalClientAfterSwitch, err := provider.NewAdditionalClient(ctx)
			require.NoError(t, err, "additional client should provided")

			require.Len(t, provider.additionalClients, 4, "additional client should stored")

			clientsType := &clissh.Client{}

			assertAdditionalClients(t, assertAdditionalClientsParams{
				defaultClient: defaultClientAfterSwitch,
				clientsType:   clientsType,
				gotAdditionalClients: append(
					[]connection.SSHClient{},
					firstAdditionalClientAfterSwitch,
					secondAdditionalClientAfterSwitch,
				),
				additionalClientsForCheck: provider.additionalClients[2:],
				expectedSession:           switchSession,
			})

			// switch to default
			_, err = provider.SwitchToDefault(ctx)
			require.NoError(t, err, "should switch")

			defaultClientAfterSwitchToDefault, err := provider.Client(ctx)
			require.NoError(t, err, "default client should provided")

			firstAdditionalClientAfterSwitchToDefault, err := provider.NewAdditionalClient(ctx)
			require.NoError(t, err, "additional client should provided")

			secondAdditionalClientAfterSwitchToDefault, err := provider.NewAdditionalClient(ctx)
			require.NoError(t, err, "additional client should provided")

			require.Len(t, provider.additionalClients, 6, "additional client should stored")

			assertAdditionalClients(t, assertAdditionalClientsParams{
				defaultClient: defaultClientAfterSwitchToDefault,
				clientsType:   clientsType,
				gotAdditionalClients: append(
					[]connection.SSHClient{},
					firstAdditionalClientAfterSwitchToDefault,
					secondAdditionalClientAfterSwitchToDefault,
				),
				additionalClientsForCheck: provider.additionalClients[4:],
				expectedSession:           defaultClient.Session(),
			})
		})
	})

	t.Run("Options", func(t *testing.T) {
		t.Run("force go-ssh but client pass force cli", func(t *testing.T) {
			test := newTest(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				mode: sshconfig.Mode{
					ForceLegacy: true,
				},
				test:        test,
				bastionPort: nil,
				port:        nil,
			})

			sett := test.Settings()

			provider := newTestProvider(sett, config, SSHClientWithForceGoSSH())
			ctx := context.TODO()

			client, err := provider.Client(ctx)
			require.NoError(t, err, "should get client")
			require.IsType(t, &gossh.Client{}, client, "client should be go client")

			tests.AssertLogMessage(
				t,
				sett,
				"Force go-ssh client from provider options",
			)
		})

		t.Run("pass no init agent to cli-ssh", func(t *testing.T) {
			test := newTest(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyPaths(t, connectionConfigParams{
				mode: sshconfig.Mode{
					ForceLegacy: true,
				},
				test:        test,
				bastionPort: nil,
				port:        nil,
			})

			assertInitNewAgent := func(t *testing.T, provider *DefaultSSHProvider, shouldInit bool) {
				ctx := context.TODO()

				client, err := provider.Client(ctx)
				require.NoError(t, err, "should get client")
				cliClient, ok := client.(*clissh.Client)
				require.True(t, ok, "client should be cli client")

				assertInitAgent := require.False
				if shouldInit {
					assertInitAgent = require.True
				}

				assertInitAgent(t, cliClient.InitializeNewAgent, "should pass init new agent to client")
			}

			sett := test.Settings()

			providerWithAgent := newTestProvider(sett, config, SSHClientWithNoInitializeAgent())
			assertInitNewAgent(t, providerWithAgent, false)

			providerWithoutAgent := NewDefaultSSHProvider(sett, config)
			assertInitNewAgent(t, providerWithoutAgent, true)
		})
	})

	t.Run("Cleanup", func(t *testing.T) {
		assertRemovePrivateKeysDir := func(t *testing.T, sett settings.Settings, provider *DefaultSSHProvider, rootPresent bool) {
			assertLog := tests.AssertNoLogMessage
			if rootPresent {
				assertLog = tests.AssertLogMessage
			}

			assertLog(t, sett, "Remove private keys dir")

			const rootDir = "lib-connection-ssh"
			var pathsInRoot []string
			rootPath := filepath.Join(sett.TmpDir(), rootDir)
			err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				if info.Name() == rootDir {
					return nil
				}

				pathsInRoot = append(pathsInRoot, path)
				return nil
			})

			if !rootPresent {
				require.Error(t, err, "walk should fail")
				require.ErrorIs(t, err, os.ErrNotExist, "root should not exist")
				return
			}

			require.NoError(t, err, "should walk")
			require.Len(t, pathsInRoot, 0, "should remove all private keys")

			require.Empty(t, provider.privateKeysTmp, "drop private key tmp")
		}

		type assertCleanupParams struct {
			sett        settings.Settings
			provider    *DefaultSSHProvider
			allClients  []connection.SSHClient
			rootPresent bool
		}

		assertCleanup := func(t *testing.T, params assertCleanupParams) {
			provider := params.provider

			var err error
			doCleanup := func() {
				err = provider.Cleanup(context.TODO())
			}

			require.NotPanics(t, doCleanup, "cleanup should not panics")
			require.NoError(t, err, "should cleanup")

			require.True(t, govalue.Nil(provider.currentClient), "should drop current client")
			require.Len(t, provider.additionalClients, 0, "should drop all additional clients")

			for i, client := range params.allClients {
				require.True(t, client.IsStopped(), "should stop all clients current client %d", i)
			}

			assertRemovePrivateKeysDir(t, params.sett, provider, params.rootPresent)

			require.False(t, provider.privateKeysPrepared, "drop private key prepared")
		}

		getProvider := func(t *testing.T) (settings.Settings, *DefaultSSHProvider, *sshconfig.ConnectionConfig) {
			test := newTest(t)
			config := testCreateSSHConnectionConfigWithPrivateKeyContent(t, connectionConfigParams{
				mode: sshconfig.Mode{
					ForceLegacy: true,
				},
				test:        test,
				bastionPort: nil,
				port:        nil,
			})

			sett := test.Settings()

			provider := newTestProvider(sett, config)

			return sett, provider, config
		}

		t.Run("stop all clients remove keys and set clients to nil", func(t *testing.T) {
			sett, provider, config := getProvider(t)

			ctx := context.TODO()

			allClients := make([]connection.SSHClient, 0, 3)

			defaultClient, err := provider.Client(ctx)
			require.NoError(t, err, "should get client")
			allClients = append(allClients, defaultClient)

			firstAdditionalClient, err := provider.NewAdditionalClient(ctx)
			require.NoError(t, err, "should create additional client")
			allClients = append(allClients, firstAdditionalClient)

			secondAdditionalClient, err := provider.NewAdditionalClient(ctx)
			require.NoError(t, err, "should create additional client")
			allClients = append(allClients, secondAdditionalClient)

			assertWritePrivateKeys(t, assertParams{
				sett:      sett,
				writeKeys: true,
				config:    config,
			})

			require.False(t, govalue.Nil(provider.currentClient), "current client should not be nil")
			require.Len(t, provider.additionalClients, 2, "should store all additional clients")
			require.True(t, firstAdditionalClient == provider.additionalClients[0], "should store additional client")
			require.True(t, secondAdditionalClient == provider.additionalClients[1], "should store additional client")

			assertCleanup(t, assertCleanupParams{
				sett:        sett,
				provider:    provider,
				allClients:  allClients,
				rootPresent: true,
			})
		})

		t.Run("without current client", func(t *testing.T) {
			sett, provider, config := getProvider(t)

			ctx := context.TODO()

			firstAdditionalClient, err := provider.NewAdditionalClient(ctx)
			require.NoError(t, err, "should create additional client")

			assertWritePrivateKeys(t, assertParams{
				sett:      sett,
				writeKeys: true,
				config:    config,
			})

			assertCleanup(t, assertCleanupParams{
				sett:        sett,
				provider:    provider,
				allClients:  []connection.SSHClient{firstAdditionalClient},
				rootPresent: true,
			})
		})

		t.Run("without all", func(t *testing.T) {
			sett, provider, config := getProvider(t)

			assertWritePrivateKeys(t, assertParams{
				sett:      sett,
				writeKeys: false,
				config:    config,
			})

			assertCleanup(t, assertCleanupParams{
				sett:        sett,
				provider:    provider,
				rootPresent: false,
			})
		})

		t.Run("safe use provider after cleanup", func(t *testing.T) {
			sett, provider, config := getProvider(t)

			ctx := context.TODO()

			client, err := provider.Client(ctx)
			require.NoError(t, err, "should get client")

			privateKeyPathBeforeCleanup := provider.privateKeysTmp

			assertWritePrivateKeys(t, assertParams{
				sett:      sett,
				writeKeys: true,
				config:    config,
			})

			assertCleanup(t, assertCleanupParams{
				sett:        sett,
				provider:    provider,
				allClients:  []connection.SSHClient{client},
				rootPresent: true,
			})

			_, err = provider.Client(ctx)
			require.NoError(t, err, "should get client")

			assertWritePrivateKeys(t, assertParams{
				sett:      sett,
				writeKeys: true,
				config:    config,
			})

			require.NotEqual(t, privateKeyPathBeforeCleanup, provider.privateKeysTmp, "should create new tmp dir")
		})
	})
}

func newTest(t *testing.T) *tests.Test {
	s := strings.Split(tests.Name(t), "/")

	res := tests.ShouldNewTest(
		t,
		s[len(s)-1],
		tests.TestWithDebug(true),
		tests.TestWithParallelRun(true),
	).WithEnvsPrefix("TEST_SSH_PROVIDER")

	res.GetLogger().InfoF("Got name: %s", res.Name())

	return res
}

func newTestProvider(sett settings.Settings, config *sshconfig.ConnectionConfig, opts ...SSHClientOption) *DefaultSSHProvider {
	notInitAgentOpts := []SSHClientOption{
		// in current suit we do not need to init agent
		SSHClientWithNoInitializeAgent(),
	}

	notInitAgentOpts = append(notInitAgentOpts, opts...)

	provider := NewDefaultSSHProvider(sett, config, notInitAgentOpts...)
	// because client does not start in suit use small sleep
	provider.goSSHStopWait = 20 * time.Millisecond

	return provider
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
	privateKeys := make([]session.AgentPrivateKey, 0, len(params.additionalPrivateKeys))
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
	mode        sshconfig.Mode
	bastionPort *int
	port        *int
	test        *tests.Test
}

func writePrivateKey(t *testing.T, params connectionConfigParams, password string) string {
	key := tests.GeneratePrivateKey(t, password)

	name := "pre-created-no-pass.id.rsa"
	if password != "" {
		name = "pre-created-pass.id.rsa"
	}

	return params.test.MustCreateTmpFile(t, key, false, name)
}

func testCreateSSHConnectionConfigWithPrivateKeyPaths(t *testing.T, params connectionConfigParams) *sshconfig.ConnectionConfig {
	keyWithoutPasswordPath := writePrivateKey(t, params, "")
	password := tests.RandPassword(12)
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
	keyWithoutPassword := tests.GeneratePrivateKey(t, "")
	password := tests.RandPassword(12)
	keyWithPassword := tests.GeneratePrivateKey(t, password)

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
	sett                      settings.Settings
	writeKeys                 bool
	provider                  *DefaultSSHProvider
	clientType                connection.SSHClient
	shouldContainError        string
	config                    *sshconfig.ConnectionConfig
	privateKeysShouldPrepared bool
}

func (a assertParams) assertPrivateKeysPrepared(t *testing.T) {
	assert := require.False
	if a.privateKeysShouldPrepared {
		assert = require.True
	}

	assert(t, a.provider.privateKeysPrepared, "should valid privateKeysPrepared")
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
		BecomePass: tests.RandPassword(12),
		AvailableHosts: []session.Host{
			{
				Host: host,
				Name: host,
			},
		},
	})
}
