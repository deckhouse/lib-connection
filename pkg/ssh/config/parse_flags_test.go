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
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deckhouse/lib-dhctl/pkg/log"
	flag "github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/tests"
)

func TestParseFlags(t *testing.T) {
	usr, err := user.Current()
	require.NoError(t, err, "could not get current user")

	currentUserName, currentHomeDir := usr.Username, usr.HomeDir

	defaultPrivateKey := func(homeDir string) AgentPrivateKey {
		return AgentPrivateKey{
			Key:        path.Join(homeDir, ".ssh", "id_rsa"),
			Passphrase: "not secure",
			IsPath:     true,
		}
	}
	// by default, we have ~/.ssh/id_rsa key
	// it can be protected with password with local development env
	defaultPrivateKeyExtractor := func(homePath string) PrivateKeyExtractorFunc {
		return func(path string, logger log.Logger) (string, error) {
			expected := filepath.Join(homePath, ".ssh", "id_rsa")
			if path != expected {
				return "", fmt.Errorf("expected %s, got %s", homePath, path)
			}

			defaultKey := defaultPrivateKey(path)

			return defaultKey.Passphrase, nil
		}
	}

	type test struct {
		name                string
		passwords           *passwordsFromUser
		envsPrefix          string
		envs                map[string]string
		arguments           []string
		opts                []ValidateOption
		hasErrorContains    string
		expected            *ConnectionConfig
		privateKeys         []*testPrivateKey
		before              func(*testing.T, *test, log.Logger)
		privateKeyExtractor PrivateKeyExtractorFunc
		test                *tests.Test
		defaultAsk          bool
	}

	beforeAddPrivateKeys := func(_ *testing.T, tst *test, _ log.Logger) {
		pathToPassword := make(map[string]string)

		for _, privateKey := range tst.privateKeys {
			tst.arguments = append(tst.arguments, fmt.Sprintf("--ssh-agent-private-keys=%s", privateKey.path))

			if tst.expected != nil {
				tst.expected.Config.PrivateKeys = append(
					tst.expected.Config.PrivateKeys, AgentPrivateKey{
						Key:        privateKey.path,
						Passphrase: privateKey.expectedPassword,
						IsPath:     true,
					},
				)
			}

			if privateKey.expectedPassword != "" {
				pathToPassword[privateKey.path] = privateKey.expectedPassword
			}
		}

		if tst.privateKeyExtractor == nil && len(pathToPassword) > 0 {
			tst.privateKeyExtractor = func(path string, _ log.Logger) (string, error) {
				return pathToPassword[path], nil
			}
		}
	}

	beforeSetSudoPasswordToExpected := func(t *testing.T, tst *test, logger log.Logger) {
		require.NotNil(t, tst.passwords, "passwords should not be nil")
		require.NotNil(t, tst.expected, "expected should not be nil")
		tst.expected.Config.SudoPassword = tst.passwords.Sudo
	}

	testCases := []test{
		{
			name:             "empty",
			passwords:        nil,
			arguments:        []string{},
			hasErrorContains: "",

			privateKeyExtractor: defaultPrivateKeyExtractor(currentHomeDir),

			expected: &ConnectionConfig{
				Config: &Config{
					Mode: Mode{
						ForceLegacy: false,
						ForceModern: false,
					},
					User: currentUserName,
					Port: intPtr(22),

					PrivateKeys: []AgentPrivateKey{
						defaultPrivateKey(currentHomeDir),
					},

					BastionUser: currentUserName,
					BastionPort: intPtr(22),
				},
				Hosts: make([]Host, 0),
			},
		},

		{
			name:      "unknown flags should processed",
			passwords: nil,
			arguments: []string{
				"--ssh-host=192.168.0.1",
				"--unknown=value",
			},
			hasErrorContains: "",

			privateKeyExtractor: defaultPrivateKeyExtractor(currentHomeDir),

			expected: &ConnectionConfig{
				Config: &Config{
					Mode: Mode{
						ForceLegacy: false,
						ForceModern: false,
					},
					User: currentUserName,
					Port: intPtr(22),

					PrivateKeys: []AgentPrivateKey{
						defaultPrivateKey(currentHomeDir),
					},

					BastionUser: currentUserName,
					BastionPort: intPtr(22),
				},
				Hosts: []Host{
					{
						Host: "192.168.0.1",
					},
				},
			},
		},

		{
			name:             "empty rewrite HOME env",
			passwords:        nil,
			arguments:        []string{},
			hasErrorContains: "",

			before: func(t *testing.T, tst *test, logger log.Logger) {
				homePath := tst.test.MustMkSubDirs(t, "testhome")
				tests.SetEnvs(t, map[string]string{
					"HOME": homePath,
				})

				tst.privateKeyExtractor = defaultPrivateKeyExtractor(homePath)
				tst.expected.Config.PrivateKeys = []AgentPrivateKey{
					defaultPrivateKey(homePath),
				}
			},

			expected: &ConnectionConfig{
				Config: &Config{
					Mode: Mode{
						ForceLegacy: false,
						ForceModern: false,
					},
					User: currentUserName,
					Port: intPtr(22),

					// PrivateKeys added in before

					BastionUser: currentUserName,
					BastionPort: intPtr(22),
				},
				Hosts: make([]Host, 0),
			},
		},

		{
			name:      "empty rewrite USER env",
			passwords: nil,
			arguments: []string{},

			hasErrorContains: "",

			envsPrefix: "EXTRACT_USER",

			before: func(t *testing.T, tst *test, logger log.Logger) {
				homePath := tst.test.MustMkSubDirs(t, "testhomeextract")

				tst.privateKeyExtractor = defaultPrivateKeyExtractor(homePath)

				tst.envs = map[string]string{
					"USER": "notexists8",
					"HOME": homePath,
				}

				tst.expected.Config.PrivateKeys = []AgentPrivateKey{
					defaultPrivateKey(homePath),
				}
			},

			expected: &ConnectionConfig{
				Config: &Config{
					Mode: Mode{
						ForceLegacy: false,
						ForceModern: false,
					},
					User: "notexists8",
					Port: intPtr(22),

					// PrivateKeys added in before

					BastionUser: "notexists8",
					BastionPort: intPtr(22),
				},
				Hosts: make([]Host, 0),
			},
		},

		{
			name:      "empty arguments and empty USER and HOME env",
			passwords: nil,
			arguments: []string{},

			hasErrorContains: "",

			envsPrefix: "EXTRACT_ENVS_EMPTY",

			before: func(t *testing.T, tst *test, logger log.Logger) {
				tst.privateKeyExtractor = defaultPrivateKeyExtractor(currentHomeDir)

				tst.envs = map[string]string{
					"USER": "",
					"HOME": "",
				}

				tst.expected.Config.PrivateKeys = []AgentPrivateKey{
					defaultPrivateKey(currentHomeDir),
				}
			},

			expected: &ConnectionConfig{
				Config: &Config{
					Mode: Mode{
						ForceLegacy: false,
						ForceModern: false,
					},
					User: currentUserName,
					Port: intPtr(22),

					// PrivateKeys added in before

					BastionUser: currentUserName,
					BastionPort: intPtr(22),
				},
				Hosts: make([]Host, 0),
			},
		},

		{
			name:      "pass private keys with all connected settings",
			passwords: nil,
			arguments: []string{
				"--ssh-bastion-host=127.0.0.1",
				"--ssh-bastion-port=2200",
				"--ssh-bastion-user=bastion",
				"--ssh-host=192.168.0.1",
				"--ssh-host=192.168.0.2",
				"--ssh-user=user",
				"--ssh-port=2201",
				"--ssh-extra-args=arg0,arg1",
				"--ssh-modern-mode",
			},

			privateKeys: []*testPrivateKey{
				{password: tests.Ptr("")},
				{password: tests.Ptr(tests.RandPassword(10))},
			},

			before:           beforeAddPrivateKeys,
			hasErrorContains: "",

			expected: &ConnectionConfig{
				Config: &Config{
					Mode: Mode{
						ForceLegacy: false,
						ForceModern: true,
					},
					User: "user",
					Port: intPtr(2201),
					// PrivateKeys added in before

					BastionUser: "bastion",
					BastionHost: "127.0.0.1",
					BastionPort: intPtr(2200),

					ExtraArgs: "arg0,arg1",
				},
				Hosts: []Host{
					{Host: "192.168.0.1"},
					{Host: "192.168.0.2"},
				},
			},
		},

		{
			name: "ask passwords",
			passwords: &passwordsFromUser{
				Sudo:    tests.RandPassword(10),
				Bastion: tests.RandPassword(10),
			},
			arguments: []string{
				"--ssh-host=192.168.0.1",
				"--ssh-user=user",
				"--ssh-port=2201",
				"--ssh-legacy-mode",
				"--ask-bastion-pass",
				"--ask-become-pass",
			},

			privateKeys: []*testPrivateKey{
				{password: tests.Ptr("")},
			},

			before: func(t *testing.T, tst *test, logger log.Logger) {
				beforeAddPrivateKeys(t, tst, logger)
				tst.expected.Config.SudoPassword = tst.passwords.Sudo
				tst.expected.Config.BastionPassword = tst.passwords.Bastion
			},

			hasErrorContains: "",

			expected: &ConnectionConfig{
				Config: &Config{
					Mode: Mode{
						ForceLegacy: true,
						ForceModern: false,
					},
					User: "user",
					Port: intPtr(2201),

					BastionUser: currentUserName,
					BastionPort: intPtr(22),

					// PrivateKeys added in before
					// Passwords added in before
				},
				Hosts: []Host{
					{Host: "192.168.0.1"},
				},
			},
		},

		{
			name: "rewrite from envs",

			arguments: []string{
				"--ssh-host=192.168.0.1",
				"--ssh-user=user",
				"--ssh-port=2201",
			},

			envsPrefix: "DHCTL",
			envs: map[string]string{
				"DHCTL_SSH_HOSTS":        "192.168.0.2,192.168.0.3",
				"DHCTL_SSH_MODERN_MODE":  "true",
				"DHCTL_SSH_LEGACY_MODE":  "false",
				"DHCTL_SSH_BASTION_PORT": "2200",
			},

			privateKeys: []*testPrivateKey{
				{password: tests.Ptr("")},
			},

			before: beforeAddPrivateKeys,

			hasErrorContains: "",

			expected: &ConnectionConfig{
				Config: &Config{
					Mode: Mode{
						ForceLegacy: false,
						ForceModern: true,
					},
					User: "user",
					Port: intPtr(2201),

					BastionUser: currentUserName,
					BastionPort: intPtr(2200),

					// PrivateKeys added in before
					// Passwords added in before
				},
				Hosts: []Host{
					{Host: "192.168.0.2"},
					{Host: "192.168.0.3"},
				},
			},
		},

		{
			name: "rewrite from envs use default os lookup",

			arguments: []string{
				"--ssh-host=192.168.0.1",
				"--ssh-user=user",
				"--ssh-port=2201",
			},

			envsPrefix: "MY",
			privateKeys: []*testPrivateKey{
				{password: tests.Ptr("")},
			},

			before: func(t *testing.T, tst *test, logger log.Logger) {
				beforeAddPrivateKeys(t, tst, logger)
				tests.SetEnvs(t, map[string]string{
					"MY_SSH_HOSTS":        "192.168.1.2,192.168.1.3",
					"MY_SSH_LEGACY_MODE":  "true",
					"MY_SSH_BASTION_PORT": "2300",
				})
			},

			hasErrorContains: "",

			expected: &ConnectionConfig{
				Config: &Config{
					Mode: Mode{
						ForceLegacy: true,
						ForceModern: false,
					},
					User: "user",
					Port: intPtr(2201),

					BastionUser: currentUserName,
					BastionPort: intPtr(2300),

					// PrivateKeys added in before
					// Passwords added in before
				},
				Hosts: []Host{
					{Host: "192.168.1.2"},
					{Host: "192.168.1.3"},
				},
			},
		},

		{
			name: "use password auth with set empty private keys env",
			passwords: &passwordsFromUser{
				Sudo: tests.RandPassword(10),
			},

			arguments: []string{
				"--ask-become-pass",
			},

			envsPrefix: "NO_KEYS",
			envs: map[string]string{
				"NO_KEYS_SSH_AGENT_PRIVATE_KEYS": "",
			},

			hasErrorContains: "",

			privateKeyExtractor: defaultPrivateKeyExtractor(currentHomeDir),

			before: beforeSetSudoPasswordToExpected,

			expected: &ConnectionConfig{
				Config: &Config{
					Mode: Mode{
						ForceLegacy: false,
						ForceModern: false,
					},
					User: currentUserName,
					Port: intPtr(22),

					PrivateKeys: make([]AgentPrivateKey, 0),

					BastionUser: currentUserName,
					BastionPort: intPtr(22),
				},
				Hosts: make([]Host, 0),
			},
		},

		{
			name: "force no private keys",
			passwords: &passwordsFromUser{
				Sudo: tests.RandPassword(10),
			},

			arguments: []string{
				"--force-no-private-keys",
				"--ask-become-pass",
			},

			hasErrorContains: "",

			privateKeyExtractor: defaultPrivateKeyExtractor(currentHomeDir),

			before: beforeSetSudoPasswordToExpected,

			expected: &ConnectionConfig{
				Config: &Config{
					Mode: Mode{
						ForceLegacy: false,
						ForceModern: false,
					},
					User: currentUserName,
					Port: intPtr(22),

					PrivateKeys: make([]AgentPrivateKey, 0),

					BastionUser: currentUserName,
					BastionPort: intPtr(22),
				},
				Hosts: make([]Host, 0),
			},
		},

		{
			name: "force no private keys force sudo password",
			passwords: &passwordsFromUser{
				Sudo: tests.RandPassword(10),
			},

			arguments: []string{
				"--force-no-private-keys",
			},

			hasErrorContains: "",

			privateKeyExtractor: defaultPrivateKeyExtractor(currentHomeDir),

			before: beforeSetSudoPasswordToExpected,

			expected: &ConnectionConfig{
				Config: &Config{
					Mode: Mode{
						ForceLegacy: false,
						ForceModern: false,
					},
					User: currentUserName,
					Port: intPtr(22),

					PrivateKeys: make([]AgentPrivateKey, 0),

					BastionUser: currentUserName,
					BastionPort: intPtr(22),
				},
				Hosts: make([]Host, 0),
			},
		},

		{
			name: "force no private keys with use agent",

			arguments: []string{
				"--force-no-private-keys",
				"--use-agent-with-no-private-keys",
			},

			hasErrorContains: "",

			privateKeyExtractor: defaultPrivateKeyExtractor(currentHomeDir),

			before: func(t *testing.T, ts *test, logger log.Logger) {
				p := ts.test.MustCreateTmpFile(t, "", false, "auth_sock")
				ts.test.WithAuthSock(p)
			},

			expected: &ConnectionConfig{
				Config: &Config{
					Mode: Mode{
						ForceLegacy: false,
						ForceModern: false,
					},
					User: currentUserName,
					Port: intPtr(22),

					SudoPassword: "",

					PrivateKeys: make([]AgentPrivateKey, 0),

					BastionUser: currentUserName,
					BastionPort: intPtr(22),

					ForceUseSSHAgent: true,
				},
				Hosts: make([]Host, 0),
			},
		},

		{
			name: "connection config",

			arguments: []string{},

			before: func(t *testing.T, tst *test, logger log.Logger) {
				validPrivateKeys := []AgentPrivateKey{
					{
						Key:        tests.GeneratePrivateKey(t, "no_secure_password"),
						Passphrase: "no_secure_password",
					},
					{
						Key: tests.GeneratePrivateKey(t, ""),
					},
				}

				config := generateConfigWithKeys(t, validPrivateKeys, `
sshPort: 2221
sshUser: ubuntu
sudoPassword: "not_secure_password"
sshBastionHost: "127.0.0.1"
sshBastionPort: 2220
sshBastionUser: bastion
legacyMode: true
sshBastionPassword: "not_secure_password_bastion"
`, "192.168.0.1", "192.168.0.2")

				configPath := tst.test.MustCreateTmpFile(t, config, false, "connection-config")

				tst.arguments = append(tst.arguments, fmt.Sprintf("--connection-config=%s", configPath))

				tst.expected.Config.PrivateKeys = validPrivateKeys
			},

			hasErrorContains: "",

			expected: &ConnectionConfig{
				Config: &Config{
					Mode: Mode{
						ForceLegacy: true,
						ForceModern: false,
					},
					User: "ubuntu",
					Port: intPtr(2221),

					BastionHost: "127.0.0.1",
					BastionUser: "bastion",
					BastionPort: intPtr(2220),

					SudoPassword:    "not_secure_password",
					BastionPassword: "not_secure_password_bastion",

					// PrivateKeys added in before
				},
				Hosts: []Host{
					{Host: "192.168.0.1"},
					{Host: "192.168.0.2"},
				},
			},
		},

		{
			name:             "empty with required hosts",
			passwords:        nil,
			arguments:        []string{},
			hasErrorContains: "SSH hosts for connection is required. Please pass hosts for connection via --ssh-host flag",
			// by default, we have ~/.ssh/id_rsa key
			// it can be protected with password with local development env
			privateKeyExtractor: defaultPrivateKeyExtractor(currentHomeDir),
			opts:                []ValidateOption{ParseWithRequiredSSHHost(true)},
		},

		{
			name:      "multiple same hosts passed",
			passwords: nil,
			arguments: []string{
				"--ssh-host=192.168.0.4",
				"--ssh-host=192.168.0.3",
				"--ssh-host=192.168.0.4",
				"--ssh-host=192.168.0.4",
				"--ssh-host=192.168.0.2",
				"--ssh-host=192.168.0.1",
				"--ssh-host=192.168.0.2",
			},
			hasErrorContains: "\thost '192.168.0.2' present multiple times 2\n\thost '192.168.0.4' present multiple times 3",
			// by default, we have ~/.ssh/id_rsa key
			// it can be protected with password with local development env
			privateKeyExtractor: defaultPrivateKeyExtractor(currentHomeDir),
			opts:                []ValidateOption{ParseWithRequiredSSHHost(true)},
		},

		{
			name:      "pass connection-config and ssh args both",
			passwords: nil,
			arguments: []string{
				"--ssh-host=192.168.0.1",
				"--connection-config=/tmp/not_exists.yaml",
			},
			hasErrorContains: "Cannot use both --connection-config and --ssh-* flags or envs at the same time",
		},

		{
			name:      "pass connection-config and ssh envs both",
			passwords: nil,
			arguments: []string{
				"--connection-config=/tmp/not_exists.yaml",
			},
			envsPrefix: "SOME",
			envs: map[string]string{
				"SOME_SSH_BASTION_PORT": "2200",
			},
			hasErrorContains: "Cannot use both --connection-config and --ssh-* flags or envs at the same time",
		},

		{
			name:      "incorrect flag type",
			passwords: nil,
			arguments: []string{
				"--ssh-bastion-port=portstr",
			},
			hasErrorContains: `invalid argument "portstr" for "--ssh-bastion-port" flag: strconv.ParseInt: parsing "portstr": invalid syntax`,
		},

		{
			name:      "incorrect env type",
			passwords: nil,
			arguments: []string{},

			envsPrefix: "TYPE",
			envs: map[string]string{
				"TYPE_SSH_BASTION_PORT": "portstr",
			},

			hasErrorContains: `Cannot convert 'portstr' to int for TYPE_SSH_BASTION_PORT`,
		},

		{
			name:      "legacy and modern mode both",
			passwords: nil,
			arguments: []string{
				"--ssh-legacy-mode",
			},

			envsPrefix: "MODE",
			envs: map[string]string{
				"MODE_SSH_MODERN_MODE": "yes",
			},

			hasErrorContains: "--ssh-legacy-mode and --ssh-modern-mode cannot be use both",
		},

		{
			name:      "connection-config not exist",
			passwords: nil,
			arguments: []string{
				"--connection-config=/tmp/not_exists.86t6ff6d.yaml",
			},
			hasErrorContains: "cannot get connection config file info for /tmp/not_exists.86t6ff6d.yaml",
		},

		{
			name:      "connection-config not regular file",
			passwords: nil,
			arguments: []string{},
			before: func(t *testing.T, tst *test, logger log.Logger) {
				configPath := tst.test.MustMkSubDirs(t, "connection-config-dir")
				tst.arguments = append(tst.arguments, fmt.Sprintf("--connection-config=%s", configPath))
			},
			hasErrorContains: "should be a file not dir",
		},

		{
			name:      "invalid private key",
			passwords: nil,
			arguments: []string{},
			privateKeys: []*testPrivateKey{
				{
					content:  "not key",
					password: tests.Ptr(""),
				},
			},

			before:           beforeAddPrivateKeys,
			hasErrorContains: "got error: ssh: no key found",
		},

		{
			name:      "invalid private key password",
			passwords: nil,
			arguments: []string{},

			privateKeys: []*testPrivateKey{
				{expectedPassword: tests.RandPassword(6)},
			},

			before: func(t *testing.T, tst *test, logger log.Logger) {
				defaultPassword := []byte(tst.privateKeys[0].expectedPassword)
				tst.privateKeyExtractor = func(path string, logger log.Logger) (string, error) {
					return terminalPrivateKeyPasswordExtractor(path, defaultPassword, logger)
				}
				beforeAddPrivateKeys(t, tst, logger)
			},
			hasErrorContains: "got error: x509: decryption password incorrect",
		},

		{
			name:      "rewrite HOME env with file",
			passwords: nil,
			arguments: []string{},

			envsPrefix: "EXTRACT_HOME",

			before: func(t *testing.T, tst *test, logger log.Logger) {
				homePath := tst.test.MustCreateTmpFile(t, "content", false, "testhome")
				tst.envs = map[string]string{
					"HOME": homePath,
				}
			},
			hasErrorContains: "Cannot get user home dir:",
		},

		{
			name: "ask passwords use default password reader",
			passwords: &passwordsFromUser{
				Sudo:    tests.RandPassword(10),
				Bastion: tests.RandPassword(10),
			},
			arguments: []string{
				"--ssh-host=192.168.0.1",
				"--ssh-user=user",
				"--ssh-port=2201",
				"--ssh-legacy-mode",
				"--ask-bastion-pass",
				"--ask-become-pass",
			},

			privateKeys: []*testPrivateKey{
				{password: tests.Ptr("")},
			},

			before: beforeAddPrivateKeys,

			defaultAsk: true,

			// because test stdin is not terminal and we do not emulate it in fast way
			// we check that in tests we got error
			hasErrorContains: "Cannot get bastion password: stdin is not a terminal, error reading password",
		},

		{
			name: "ask private key password with default password reader",
			arguments: []string{
				"--ssh-host=192.168.0.1",
				"--ssh-user=user",
				"--ssh-port=2201",
				"--ssh-legacy-mode",
			},

			privateKeys: []*testPrivateKey{
				{password: tests.Ptr(tests.RandPassword(10))},
			},

			before: func(t *testing.T, tst *test, logger log.Logger) {
				for _, privateKey := range tst.privateKeys {
					tst.arguments = append(tst.arguments, fmt.Sprintf("--ssh-agent-private-keys=%s", privateKey.path))
				}
			},

			defaultAsk: true,

			// because test stdin is not terminal and we do not emulate it in fast way
			// we check that in tests we got error
			hasErrorContains: "stdin is not a terminal, error reading password",
		},

		{
			name: "force no private keys no sudo password",
			passwords: &passwordsFromUser{
				Sudo: "",
			},

			arguments: []string{
				"--force-no-private-keys",
			},

			hasErrorContains: "No auth methods configured. Please pass --ssh-agent-private-keys and/or --ask-become-pass or --force-no-private-keys with --ask-become-pass or --force-no-private-keys with --use-agent-with-no-private-keys",

			privateKeyExtractor: defaultPrivateKeyExtractor(currentHomeDir),
		},

		{
			name: "force no private keys with use agent no sock env",

			arguments: []string{
				"--force-no-private-keys",
				"--use-agent-with-no-private-keys",
			},

			hasErrorContains: "pass empty path for auth socket from env SSH_AUTH_SOCK",

			privateKeyExtractor: defaultPrivateKeyExtractor(currentHomeDir),
		},

		{
			name: "force no private keys with use agent incorrect sock env",

			arguments: []string{
				"--force-no-private-keys",
				"--use-agent-with-no-private-keys",
			},

			hasErrorContains: "auth socket from env SSH_AUTH_SOCK path",

			privateKeyExtractor: defaultPrivateKeyExtractor(currentHomeDir),

			before: func(t *testing.T, ts *test, logger log.Logger) {
				p := ts.test.MustMkSubDirs(t, "auth_sock")
				ts.test.WithAuthSock(p)
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			tst := tests.ShouldNewTest(t, testCase.name)
			logger := tst.Settings().Logger()

			testCase.test = tst

			keys := newTestPrivateKeys(tst, testCase.privateKeys)
			keys.create(t)

			if testCase.before != nil {
				testCase.before(t, &testCase, logger)
			}

			sett := tst.Settings()

			parser := NewFlagsParser(sett)
			parser.WithEnvsPrefix(testCase.envsPrefix)

			if !testCase.defaultAsk {
				parser.WithAsk(func(promt string) ([]byte, error) {
					if testCase.passwords == nil {
						return nil, fmt.Errorf("no passwords set")
					}

					switch promt {
					case "[bastion] Password: ":
						return []byte(testCase.passwords.Bastion), nil
					case "[sudo] Password: ":
						return []byte(testCase.passwords.Sudo), nil
					default:
						return nil, fmt.Errorf("unknown prompt")
					}
				})
			}

			if len(testCase.envs) > 0 {
				parser.WithEnvsLookup(func(name string) (string, bool) {
					val, ok := testCase.envs[name]
					return val, ok
				})
			}

			if testCase.privateKeyExtractor != nil {
				parser.WithPrivateKeyPasswordExtractor(testCase.privateKeyExtractor)
			}

			flagSetName := strings.ReplaceAll(testCase.name, " ", "-")
			flagSetName = strings.ReplaceAll(flagSetName, ":", "-")
			flagSetName = "test-parse" + flagSetName

			fset := flag.NewFlagSet(flagSetName, flag.ContinueOnError)
			flags, err := parser.InitFlags(fset)
			require.NoError(t, err, "init flags")

			config, err := flags.ExtractConfig(testCase.arguments, testCase.opts...)
			assertConnectionConfig(t, connectionConfigAssertParams{
				hasErrorContains: testCase.hasErrorContains,
				err:              err,
				got:              config,
				expected:         testCase.expected,
				logger:           sett.Logger(),
			})
		})
	}

	t.Run("ParseFlagsAndExtractConfig", func(t *testing.T) {
		t.Run("with args and no FlagSet", func(t *testing.T) {
			params := defaultArgsForParseFlagsAndExtractConfig(t, "no_flag_set")
			assertParseAndExtract(t, params, nil)
		})

		t.Run("with args and with FlagSet", func(t *testing.T) {
			params := defaultArgsForParseFlagsAndExtractConfig(t, "with_flag_set")

			flagSet := newParseFlagsAndExtractConfigFlagSet("test-connection-flagset", params)

			assertParseAndExtract(t, params, flagSet.flagSet)

			flagSet.assertAdditionalFlagsParsed(t)
		})

		t.Run("without args and with FlagSet", func(t *testing.T) {
			params := defaultArgsForParseFlagsAndExtractConfig(t, "without_flag_set")

			// use subtest for safe rewrite os.Args
			// we cannot use pass args with -args because we can run test from IDE
			//nolint:gosec
			cmd := exec.Command(os.Args[0], "-test.run=TestParseFlagsAndExtractConfigNoArgs")
			cmd.Env = append(
				os.Environ(),
				fmt.Sprintf("TEST_NO_ARGS=%s",
					strings.Join(params.arguments, " "),
				),
			)

			output, err := cmd.CombinedOutput()
			require.NoError(
				t,
				err,
				"TestParseFlagsAndExtractConfigNoArgs should run without error: %s",
				string(output),
			)

			params.test.GetLogger().InfoF("Got output from TestParseFlagsAndExtractConfigNoArgs:\n%s", string(output))
		})
	})
}

func TestParseFlagsNoInitialize(t *testing.T) {
	getParser := func(t *testing.T) *FlagsParser {
		test := tests.ShouldNewTest(t, tests.Name(t))
		return NewFlagsParser(test.Settings())
	}

	assertError := func(t *testing.T, config *ConnectionConfig, err error, contains string) {
		require.Error(t, err, "should not have an error")
		require.Contains(t, err.Error(), contains)
		require.Nil(t, config)
	}

	t.Run("Extract without initialize", func(t *testing.T) {
		flags := &Flags{
			BastionHost: "127.0.0.1",
			BastionUser: "bastion",
			BastionPort: 22201,

			User: "user",
			Port: 22202,

			Hosts: []string{"192.168.0.1"},
		}

		parser := getParser(t)
		config, err := parser.ExtractConfigAfterParse(flags, ParseWithRequiredSSHHost(true))
		assertError(t, config, err, "Call InitFlags first and pass Flags from result of InitFlags")
	})

	t.Run("Extract from no parsed flagset", func(t *testing.T) {
		flagSet := flag.NewFlagSet("no-parsed", flag.ContinueOnError)
		parser := getParser(t)
		flags, err := parser.InitFlags(flagSet)
		require.NoError(t, err, "init flags should initialized")
		config, err := parser.ExtractConfigAfterParse(flags, ParseWithRequiredSSHHost(true))
		assertError(t, config, err, "flagsSet is not parsed. Call flag.Parse or flag.FlagSet.Parse before extract config")
	})

	t.Run("Init config if flags already parsed", func(t *testing.T) {
		params := &parseFlagsAndExtractConfigParams{}
		flagSet := newParseFlagsAndExtractConfigFlagSet("already-parsed", params)
		flagSet.parseOnlyAdditional(t)

		parser := getParser(t)
		flags, err := parser.InitFlags(flagSet.flagSet)
		assertError(t, nil, err, "Flags already parsed")
		require.Nil(t, flags, "flags should be nil")
	})

	t.Run("ParseFlagsAndExtractConfig if flags already parsed", func(t *testing.T) {
		params := &parseFlagsAndExtractConfigParams{}
		flagSet := newParseFlagsAndExtractConfigFlagSet("already-parsed-parse-extract", params)
		flagSet.parseOnlyAdditional(t)

		parser := getParser(t)
		config, err := parser.ParseFlagsAndExtractConfig(make([]string, 0), flagSet.flagSet)
		assertError(t, config, err, "Flags already parsed")
	})
}

func TestParseFlagsAndExtractConfigNoArgs(t *testing.T) {
	argsStr, ok := os.LookupEnv("TEST_NO_ARGS")
	argsStr = strings.TrimSpace(argsStr)

	if !ok || argsStr == "" {
		t.Skip("Run TestParseFlagsAndExtractConfigNoArgs directly")
	}

	privateKeyPath := ""
	// split by -- for safe process arguments with spaces
	argsParts := strings.Split(argsStr, "--")
	require.NotEmpty(t, argsParts, "args should not be empty")

	testArgs := make([]string, 0, len(argsParts))
	for _, arg := range argsParts {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			continue
		}

		if !strings.HasPrefix(arg, "--") {
			arg = fmt.Sprintf("--%s", arg)
		}

		testArgs = append(testArgs, arg)
	}

	const privateKeyArg = "--ssh-agent-private-keys="

	for _, arg := range testArgs {
		if strings.HasPrefix(arg, privateKeyArg) {
			privateKeyPath = strings.TrimPrefix(arg, privateKeyArg)
			privateKeyPath = strings.TrimSpace(privateKeyPath)
			break
		}
	}

	require.NotEmpty(
		t,
		privateKeyPath,
		"privateKeyPath should present in args: %v",
		strings.Join(testArgs, " "),
	)

	fmt.Printf("os.Args after parse: %s\n", strings.Join(testArgs, " "))

	params := defaultArgsForParseFlagsAndExtractConfig(t, "without_args", &testPrivateKey{
		path:            privateKeyPath,
		readKeyFromPath: true,
	})

	// drop arguments for extract additional arguments
	params.arguments = nil

	flagSet := newParseFlagsAndExtractConfigFlagSet("test-connection-without-args", params)

	require.Len(t, params.arguments, 1, "should add additional arguments")

	oldArgs := os.Args
	t.Cleanup(func() {
		os.Args = oldArgs
	})

	withAdditional := []string{
		os.Args[0],
		params.arguments[0],
	}

	withAdditional = append(withAdditional, testArgs...)
	os.Args = withAdditional

	// should extract from os.Args
	params.arguments = nil

	assertParseAndExtract(t, params, flagSet.flagSet)
	flagSet.assertAdditionalFlagsParsed(t)
}

func TestParseFlagsHelp(t *testing.T) {
	tests.AssertParseFlagsHelp(t, tests.AssertParseFlagsHelpParams{
		ExpectedFlags: 15,
		Name:          "lib-connection-ssh-internal",
		Provider: func(sett settings.Settings, envsPrefix string) tests.TestFlagsParser {
			parser := NewFlagsParser(sett)
			parser.WithEnvsPrefix(envsPrefix)

			return &testHelpParser{parser: parser}
		},
	})
}

type testHelpParser struct {
	parser *FlagsParser
}

func (p *testHelpParser) InitFlags(flagSet *flag.FlagSet) (*flag.FlagSet, error) {
	initFlags, err := p.parser.InitFlags(flagSet)
	if err != nil {
		return nil, err
	}

	return initFlags.baseFlags.FlagSet(), nil
}

type parseFlagsAndExtractConfigFlagSet struct {
	additionalParam string
	flagSet         *flag.FlagSet
}

func newParseFlagsAndExtractConfigFlagSet(name string, params *parseFlagsAndExtractConfigParams) *parseFlagsAndExtractConfigFlagSet {
	res := &parseFlagsAndExtractConfigFlagSet{}

	flagSet := flag.NewFlagSet(name, flag.ContinueOnError)
	flagSet.StringVar(&res.additionalParam, "my-param", "", "test argument")

	res.flagSet = flagSet

	params.arguments = append(params.arguments, res.additionalArguments()...)

	return res
}

func (s *parseFlagsAndExtractConfigFlagSet) additionalArguments() []string {
	return []string{
		"--my-param=val",
	}
}

func (s *parseFlagsAndExtractConfigFlagSet) parseOnlyAdditional(t *testing.T) {
	err := s.flagSet.Parse(s.additionalArguments())
	require.NoError(t, err, "should parse only additional flags")
	s.assertAdditionalFlagsParsed(t)
}

func (s *parseFlagsAndExtractConfigFlagSet) assertAdditionalFlagsParsed(t *testing.T) {
	require.Equal(t, s.additionalParam, "val", "should parse additional argument")
}

type parseFlagsAndExtractConfigParams struct {
	arguments []string
	expected  *ConnectionConfig
	test      *tests.Test
}

func defaultArgsForParseFlagsAndExtractConfig(t *testing.T, name string, overrideKeys ...*testPrivateKey) *parseFlagsAndExtractConfigParams {
	tst := tests.ShouldNewTest(t, name)

	if len(overrideKeys) == 0 {
		overrideKeys = []*testPrivateKey{
			{password: tests.Ptr("")},
		}
	}

	keys := newTestPrivateKeys(tst, overrideKeys)
	keys.create(t)

	key := keys.keys[0]

	arguments := []string{
		"--ssh-bastion-host=127.0.0.1",
		"--ssh-bastion-port=2200",
		"--ssh-bastion-user=bastion",
		"--ssh-host=192.168.0.1",
		"--ssh-host=192.168.0.2",
		"--ssh-user=user",
		"--ssh-port=2201",
		"--ssh-extra-args=arg0,arg1",
		"--ssh-modern-mode",
		fmt.Sprintf("--ssh-agent-private-keys=%s", key.path),
	}

	expected := &ConnectionConfig{
		Config: &Config{
			Mode: Mode{
				ForceLegacy: false,
				ForceModern: true,
			},
			User: "user",
			Port: intPtr(2201),

			PrivateKeys: []AgentPrivateKey{
				{
					Key:        key.path,
					Passphrase: "",
					IsPath:     true,
				},
			},

			BastionUser: "bastion",
			BastionHost: "127.0.0.1",
			BastionPort: intPtr(2200),

			ExtraArgs: "arg0,arg1",
		},
		Hosts: []Host{
			{Host: "192.168.0.1"},
			{Host: "192.168.0.2"},
		},
	}

	return &parseFlagsAndExtractConfigParams{
		arguments: arguments,
		expected:  expected,
		test:      tst,
	}
}

func assertParseAndExtract(t *testing.T, params *parseFlagsAndExtractConfigParams, flagSet *flag.FlagSet) {
	logger := params.test.GetLogger()

	name := t.Name()
	namesSet := strings.Split(name, "/")
	require.NotEmpty(t, namesSet, "nameSet should not be empty")

	prefix := namesSet[len(namesSet)-1]
	prefix = strings.ReplaceAll(prefix, " ", "_")
	prefix = strings.ReplaceAll(prefix, ":", "_")
	prefix = strings.ToTitle(prefix)

	logger.InfoF("Got prefix: %s", prefix)

	parser := NewFlagsParser(params.test.Settings())
	parser.WithEnvsPrefix(prefix)

	config, err := parser.ParseFlagsAndExtractConfig(params.arguments, flagSet, ParseWithRequiredSSHHost(true))

	assertConnectionConfig(t, connectionConfigAssertParams{
		hasErrorContains: "",
		err:              err,
		got:              config,
		expected:         params.expected,
		logger:           logger,
	})
}

type testPrivateKey struct {
	path             string
	password         *string
	expectedPassword string
	content          string
	readKeyFromPath  bool
}

func (k *testPrivateKey) processKeyPath(t *testing.T, logger log.Logger) bool {
	if k.path == "" {
		return false
	}

	if !k.readKeyFromPath {
		logger.InfoF("Private path present %s Skip creating", k.path)
		return true
	}

	content, err := os.ReadFile(k.path)
	require.NoError(t, err, "cannot read private key %s", k.path)
	k.content = string(content)

	logger.InfoF("Private path %s content read successfully", k.path)

	return true
}

type testPrivateKeys struct {
	test *tests.Test

	keys []*testPrivateKey
}

func newTestPrivateKeys(test *tests.Test, keys []*testPrivateKey) *testPrivateKeys {
	return &testPrivateKeys{
		test: test,
		keys: keys,
	}
}

func (k *testPrivateKeys) create(t *testing.T) {
	if len(k.keys) == 0 {
		return
	}

	logger := k.test.GetLogger()

	for i, key := range k.keys {
		if key.processKeyPath(t, logger) {
			continue
		}

		password := key.password
		if password == nil {
			pass := tests.RandPassword(12)
			password = &pass
		}

		keyContent := key.content
		if keyContent == "" {
			keyContent = tests.GeneratePrivateKey(t, *password)
		} else {
			logger.InfoF("Private key content present for %d Skip generating", i)
		}

		keyID := k.test.GenerateID(fmt.Sprintf("%d", i))

		keyPath := k.test.MustCreateFile(t, keyContent, false, fmt.Sprintf("id_rsa.%s", keyID))
		logger.InfoF("Private key %s written", keyPath)

		key.path = keyPath
		key.password = password
		key.content = keyContent
		if key.expectedPassword == "" {
			key.expectedPassword = *password
		}
	}
}
