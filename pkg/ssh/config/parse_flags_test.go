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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/log"
	flag "github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
)

func TestParseFlagsHelp(t *testing.T) {
	oldStdErr := os.Stderr
	restoreStderr := func() {
		os.Stderr = oldStdErr
	}

	t.Cleanup(restoreStderr)

	sett := testSettings()
	logger := sett.Logger()

	// Create a pipe
	pr, pw, err := os.Pipe()
	require.NoError(t, err, "pipes should created")

	os.Stderr = pw

	var wg sync.WaitGroup
	wg.Add(1)

	var buf bytes.Buffer

	closed := false

	closePipes := func() {
		if closed {
			return
		}

		// hack to wait write all
		time.Sleep(3 * time.Second)

		if err := pr.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			logger.ErrorF("Error closing read pipe: %v", err)
		}

		if err := pw.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			logger.ErrorF("Error closing read pipe: %v", err)
		}

		wg.Wait()

		if err := bufio.NewWriter(&buf).Flush(); err != nil {
			logger.ErrorF("Error flushing buf: %v", err)
		}

		closed = true
	}

	t.Cleanup(closePipes)

	hasCopyErr := func(err error) bool {
		if err == nil {
			return false
		}

		if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
			return false
		}

		return true
	}

	go func() {
		defer wg.Done()
		_, err := io.Copy(&buf, pr)
		// Copy all content from the pipe reader to the buffer
		if err != nil && hasCopyErr(err) {
			logger.ErrorF("Error copying data from stderr: %v", err)
		}
	}()

	t.Cleanup(func() {
		closePipes()
		restoreStderr()
		if t.Failed() {
			out := buf.String()
			logger.InfoF("Got usage from Parse:")
			logger.InfoF("%s", out)
		}
	})

	// no use require because all stdout rewrite to buf
	assertNoError := func(t *testing.T, msg string, err error) {
		if err != nil {
			restoreStderr()
			logger.ErrorF("%s: %v", msg, err)
			t.FailNow()
		}
	}

	flagSet := flag.NewFlagSet("ssh-help", flag.ContinueOnError)

	parser := NewFlagsParser(sett)
	_, err = parser.InitFlags(flagSet)
	assertNoError(t, "Flags init failed", err)

	err = flagSet.Parse([]string{"--help"})
	if !errors.Is(err, flag.ErrHelp) {
		assertNoError(t, "Flags parse failed. Should return ErrHelp", fmt.Errorf("not help: %w", err))
	}
	// stop writing
	closePipes()

	const usagePrefix = "Usage of ssh-help:\n"

	out := buf.String()
	if !strings.Contains(out, usagePrefix) {
		assertNoError(t, "Flags help failed", fmt.Errorf("not contains usage prefix"))
	}

	out = strings.TrimPrefix(out, usagePrefix)
	out = strings.TrimSuffix(out, "\n")

	expectedFlags := 13

	lines := strings.Split(out, "\n")
	linesCount := len(lines)

	if linesCount != expectedFlags {
		assertNoError(
			t,
			fmt.Sprintf("Flags help failed \n%s\n", out), fmt.Errorf(
				"not contains all flags should %d  got %d", expectedFlags, linesCount,
			))
	}

	envMsgRe := regexp.MustCompile(`\(Can rewrite with [A-Z_]+ env\)`)

	notContainsEnv := make([]string, 0)
	for _, line := range lines {
		if !envMsgRe.MatchString(line) {
			notContainsEnv = append(notContainsEnv, line)
		}
	}

	if len(notContainsEnv) > 0 {
		assertNoError(t,
			"Flags help failed",
			fmt.Errorf(
				"not contains env vars for:\n %v",
				strings.Join(notContainsEnv, "\n"),
			),
		)
	}
}

func TestParseFlags(t *testing.T) {
	usr, err := user.Current()
	require.NoError(t, err, "could not get current user")

	currentUserName, currentHomeDir := usr.Username, usr.HomeDir

	defaultPrivateKey := AgentPrivateKey{
		Key:        "content",
		Passphrase: "not secure",
	}

	// by default, we have ~/.ssh/id_rsa key
	// it can be protected with password with local development env
	defaultPrivateKeyExtractor := func(homePath string) PrivateKeyExtractorFunc {
		return func(path string, logger log.Logger) (content string, password string, err error) {
			expected := filepath.Join(homePath, ".ssh", "id_rsa")
			if path != expected {
				return "", "", fmt.Errorf("expected %s, got %s", homePath, path)
			}

			return defaultPrivateKey.Key, defaultPrivateKey.Passphrase, nil
		}
	}

	type test struct {
		name                  string
		passwords             *passwordsFromUser
		envsPrefix            string
		envs                  map[string]string
		arguments             []string
		opts                  []ValidateOption
		hasErrorContains      string
		hasParseErrorContains string
		expected              *ConnectionConfig
		privateKeys           []*testPrivateKey
		before                func(*testing.T, *test, log.Logger)
		privateKeyExtractor   PrivateKeyExtractorFunc
		tmpDir                *testTmpDir
		defaultAsk            bool
	}

	beforeAddPrivateKeys := func(t *testing.T, tst *test, logger log.Logger) {
		pathToPassword := make(map[string]string)
		pathToContent := make(map[string]string)

		for _, privateKey := range tst.privateKeys {
			tst.arguments = append(tst.arguments, fmt.Sprintf("--ssh-agent-private-keys=%s", privateKey.path))

			if tst.expected != nil {
				tst.expected.Config.PrivateKeys = append(
					tst.expected.Config.PrivateKeys, AgentPrivateKey{
						Key:        privateKey.content,
						Passphrase: privateKey.expectedPassword,
					},
				)
			}

			if privateKey.expectedPassword != "" {
				pathToPassword[privateKey.path] = privateKey.expectedPassword
			}

			pathToContent[privateKey.path] = privateKey.content
		}

		if tst.privateKeyExtractor == nil && len(pathToPassword) > 0 {
			tst.privateKeyExtractor = func(path string, _ log.Logger) (string, string, error) {
				content, ok := pathToContent[path]
				if !ok {
					return "", "", fmt.Errorf("content for path %s not found", path)
				}

				return content, pathToPassword[path], nil
			}
		}
	}

	tests := []test{
		{
			name:             "empty",
			passwords:        nil,
			arguments:        []string{},
			hasErrorContains: "",

			privateKeyExtractor: defaultPrivateKeyExtractor(currentHomeDir),

			expected: &ConnectionConfig{
				Config: &Config{
					Mode: Mode{
						ForceLegacy:     false,
						ForceModernMode: false,
					},
					User: currentUserName,
					Port: intPtr(22),

					PrivateKeys: []AgentPrivateKey{defaultPrivateKey},

					BastionUser: currentUserName,
					BastionPort: intPtr(22),
				},
				Hosts: make([]Host, 0),
			},
		},

		{
			name:             "empty rewrite HOME env",
			passwords:        nil,
			arguments:        []string{},
			hasErrorContains: "",

			before: func(t *testing.T, tst *test, logger log.Logger) {
				homePath := tst.tmpDir.createSubDir(t, "testhome")
				setEnvs(t, map[string]string{
					"HOME": homePath,
				})

				tst.privateKeyExtractor = defaultPrivateKeyExtractor(homePath)
			},

			expected: &ConnectionConfig{
				Config: &Config{
					Mode: Mode{
						ForceLegacy:     false,
						ForceModernMode: false,
					},
					User: currentUserName,
					Port: intPtr(22),

					PrivateKeys: []AgentPrivateKey{defaultPrivateKey},

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
				homePath := tst.tmpDir.createSubDir(t, "testhomeextract")

				tst.privateKeyExtractor = defaultPrivateKeyExtractor(homePath)

				tst.envs = map[string]string{
					"USER": "notexists8",
					"HOME": homePath,
				}
			},

			expected: &ConnectionConfig{
				Config: &Config{
					Mode: Mode{
						ForceLegacy:     false,
						ForceModernMode: false,
					},
					User: "notexists8",
					Port: intPtr(22),

					PrivateKeys: []AgentPrivateKey{defaultPrivateKey},

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
			},

			expected: &ConnectionConfig{
				Config: &Config{
					Mode: Mode{
						ForceLegacy:     false,
						ForceModernMode: false,
					},
					User: currentUserName,
					Port: intPtr(22),

					PrivateKeys: []AgentPrivateKey{defaultPrivateKey},

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
				{password: stringPtr("")},
				{password: stringPtr(RandPassword(10))},
			},

			before:           beforeAddPrivateKeys,
			hasErrorContains: "",

			expected: &ConnectionConfig{
				Config: &Config{
					Mode: Mode{
						ForceLegacy:     false,
						ForceModernMode: true,
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
				Sudo:    RandPassword(10),
				Bastion: RandPassword(10),
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
				{password: stringPtr("")},
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
						ForceLegacy:     true,
						ForceModernMode: false,
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
				"DHCTL_SSH_BASTION_PORT": "2200",
			},

			privateKeys: []*testPrivateKey{
				{password: stringPtr("")},
			},

			before: beforeAddPrivateKeys,

			hasErrorContains: "",

			expected: &ConnectionConfig{
				Config: &Config{
					Mode: Mode{
						ForceLegacy:     false,
						ForceModernMode: true,
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
				{password: stringPtr("")},
			},

			before: func(t *testing.T, tst *test, logger log.Logger) {
				beforeAddPrivateKeys(t, tst, logger)
				setEnvs(t, map[string]string{
					"MY_SSH_HOSTS":        "192.168.1.2,192.168.1.3",
					"MY_SSH_LEGACY_MODE":  "true",
					"MY_SSH_BASTION_PORT": "2300",
				})
			},

			hasErrorContains: "",

			expected: &ConnectionConfig{
				Config: &Config{
					Mode: Mode{
						ForceLegacy:     true,
						ForceModernMode: false,
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
			name: "connection config",

			arguments: []string{},

			before: func(t *testing.T, tst *test, logger log.Logger) {
				validPrivateKeys := []AgentPrivateKey{
					{
						Key:        generateKey(t, "no_secure_password"),
						Passphrase: "no_secure_password",
					},
					{
						Key: generateKey(t, ""),
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

				path := tst.tmpDir.writeFile(t, config, "connection-config")

				tst.arguments = append(tst.arguments, fmt.Sprintf("--connection-config=%s", path))

				tst.expected.Config.PrivateKeys = validPrivateKeys
			},

			hasErrorContains: "",

			expected: &ConnectionConfig{
				Config: &Config{
					Mode: Mode{
						ForceLegacy:     true,
						ForceModernMode: false,
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
			name:      "unknown flag",
			passwords: nil,
			arguments: []string{
				"--ssh-host=192.168.0.1",
				"--unknown=value",
			},
			hasParseErrorContains: "unknown flag: --unknown",
		},

		{
			name:      "incorrect flag type",
			passwords: nil,
			arguments: []string{
				"--ssh-bastion-port=portstr",
			},
			hasParseErrorContains: `flag: strconv.ParseInt: parsing "portstr": invalid syntax`,
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
			hasErrorContains: "Cannot get connection config file info for /tmp/not_exists.86t6ff6d.yaml",
		},

		{
			name:      "connection-config not regular file",
			passwords: nil,
			arguments: []string{},
			before: func(t *testing.T, tst *test, logger log.Logger) {
				path := tst.tmpDir.createSubDir(t, "connection-config-dir")
				tst.arguments = append(tst.arguments, fmt.Sprintf("--connection-config=%s", path))
			},
			hasErrorContains: "should be regular file",
		},

		{
			name:      "invalid private key",
			passwords: nil,
			arguments: []string{},
			privateKeys: []*testPrivateKey{
				{
					content:  "not key",
					password: stringPtr(""),
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
				{expectedPassword: RandPassword(6)},
			},

			before: func(t *testing.T, tst *test, logger log.Logger) {
				defaultPassword := []byte(tst.privateKeys[0].expectedPassword)
				tst.privateKeyExtractor = func(path string, logger log.Logger) (string, string, error) {
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
				homePath := tst.tmpDir.writeFile(t, "content", "testhome")
				tst.envs = map[string]string{
					"HOME": homePath,
				}
			},
			hasErrorContains: "Cannot get user home dir:",
		},

		{
			name: "ask passwords use default password reader",
			passwords: &passwordsFromUser{
				Sudo:    RandPassword(10),
				Bastion: RandPassword(10),
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
				{password: stringPtr("")},
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
				{password: stringPtr(RandPassword(10))},
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
	}

	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			sett := testSettings()
			logger := sett.Logger()

			tmpDir := newTestTmpDir(t, tst.name, logger)

			tst.tmpDir = tmpDir

			keys := newTestPrivateKeys(tmpDir, tst.privateKeys)
			keys.create(t)

			if tst.before != nil {
				tst.before(t, &tst, logger)
			}

			parser := NewFlagsParser(sett).
				WithEnvsPrefix(tst.envsPrefix)

			if !tst.defaultAsk {
				parser.WithAsk(func(promt string) ([]byte, error) {
					if tst.passwords == nil {
						return nil, fmt.Errorf("no passwords set")
					}

					switch true {
					case promt == "[bastion] Password: ":
						return []byte(tst.passwords.Bastion), nil
					case promt == "[sudo] Password: ":
						return []byte(tst.passwords.Sudo), nil
					default:
						return nil, fmt.Errorf("unknown prompt")
					}
				})
			}

			if len(tst.envs) > 0 {
				parser.WithEnvsLookup(func(name string) (string, bool) {
					val, ok := tst.envs[name]
					return val, ok
				})
			}

			if tst.privateKeyExtractor != nil {
				parser.WithPrivateKeyPasswordExtractor(tst.privateKeyExtractor)
			}

			flagSetName := strings.ReplaceAll(tst.name, " ", "-")
			flagSetName = strings.ReplaceAll(flagSetName, ":", "-")
			flagSetName = "test-parse" + flagSetName

			fset := flag.NewFlagSet(flagSetName, flag.ContinueOnError)
			flags, err := parser.InitFlags(fset)
			require.NoError(t, err, "init flags")

			err = fset.Parse(tst.arguments)
			if tst.hasParseErrorContains != "" {
				require.Error(t, err, "should parse error")
				require.Contains(t, err.Error(), tst.hasParseErrorContains, "should parse error contains")
				return
			} else {
				require.NoError(t, err, "parse flags")
			}

			config, err := parser.ExtractConfigAfterParse(flags, tst.opts...)
			assertConnectionConfig(t, connectionConfigAssertParams{
				hasErrorContains: tst.hasErrorContains,
				err:              err,
				got:              config,
				expected:         tst.expected,
				logger:           sett.Logger(),
			})
		})
	}
}

type testPrivateKey struct {
	path             string
	password         *string
	expectedPassword string
	content          string
}

type testTmpDir struct {
	id     string
	tmpDir string
	logger log.Logger
	name   string

	alreadyCleanup bool
}

type testPrivateKeys struct {
	*testTmpDir

	keys []*testPrivateKey
}

func newTestPrivateKeys(tmpDir *testTmpDir, keys []*testPrivateKey) *testPrivateKeys {
	return &testPrivateKeys{
		testTmpDir: tmpDir,
		keys:       keys,
	}
}

func (k *testPrivateKeys) create(t *testing.T) {
	if len(k.keys) == 0 {
		return
	}

	for i, key := range k.keys {
		if key.path != "" {
			k.logger.InfoF("Private path present %s Skip creating", key.path)
			continue
		}

		password := key.password
		if password == nil {
			pass := RandPassword(12)
			password = &pass
		}

		keyContent := key.content
		if keyContent == "" {
			keyContent = generateKey(t, *password)
		} else {
			k.logger.InfoF("Private key content present for %d Skip generating", i)
		}

		keyID := GenerateID(k.name, fmt.Sprintf("%d", i))

		path := k.writeFile(t, keyContent, fmt.Sprintf("id_rsa.%s", keyID))
		k.logger.InfoF("Private key %s written", path)

		key.path = path
		key.password = password
		key.content = keyContent
		if key.expectedPassword == "" {
			key.expectedPassword = *password
		}
	}
}

func stringPtr(s string) *string {
	return &s
}
