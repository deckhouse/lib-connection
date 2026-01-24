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
		t.Run("Fill defaults", func(t *testing.T) {
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
}

type connectionConfigParams struct {
	sett        settings.Settings
	mode        sshconfig.Mode
	bastionPort *int
	port        *int
}

func testCreateSSHConnectionConfigWithPrivateKeyPaths(t *testing.T, params connectionConfigParams) *sshconfig.ConnectionConfig {
	writePrivateKey := func(t *testing.T, password string) string {
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

	keyWithoutPasswordPath := writePrivateKey(t, "")
	password := RandPassword(12)
	keyWithPasswordPath := writePrivateKey(t, password)

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

	assertPrivateKeysAddedInSession(t, client, params.config.Config.PrivateKeys)
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

func intPtr(i int) *int {
	return &i
}
