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

	// by default, we have ~/.ssh/id_rsa key
	// it can be protected with password with local development env
	defaultPrivateKeyExtractor := func(path string, _ log.Logger) (string, string, error) {
		expectedPath := filepath.Join(currentHomeDir, ".ssh", "id_rsa")
		if path != expectedPath {
			return "", "", fmt.Errorf("expected %s, got %s", expectedPath, path)
		}

		return "content", "not secure", nil
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
	}

	beforeAddPrivateKeys := func(t *testing.T, tst *test, logger log.Logger) {
		pathToPassword := make(map[string]string)
		pathToContent := make(map[string]string)

		for _, privateKey := range tst.privateKeys {
			tst.arguments = append(tst.arguments, fmt.Sprintf("--ssh-agent-private-keys=%s", privateKey.path))

			tst.expected.Config.PrivateKeys = append(
				tst.expected.Config.PrivateKeys, AgentPrivateKey{
					Key:        privateKey.content,
					Passphrase: privateKey.expectedPassword,
				},
			)

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

			privateKeyExtractor: defaultPrivateKeyExtractor,
			expected: &ConnectionConfig{
				Config: &Config{
					Mode: Mode{
						ForceLegacy:     false,
						ForceModernMode: false,
					},
					User: currentUserName,
					Port: intPtr(22),
					PrivateKeys: []AgentPrivateKey{
						{
							Key:        "content",
							Passphrase: "not secure",
						},
					},
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
			passwords: &passwordsFromUser{
				Sudo:    RandPassword(10),
				Bastion: RandPassword(10),
			},
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
			name:             "empty with required hosts",
			passwords:        nil,
			arguments:        []string{},
			hasErrorContains: "SSH hosts for connection is required. Please pass hosts for connection via --ssh-host flag",
			// by default, we have ~/.ssh/id_rsa key
			// it can be protected with password with local development env
			privateKeyExtractor: defaultPrivateKeyExtractor,
			opts:                []ValidateOption{ParseWithRequiredSSHHost(true)},
		},
	}

	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			sett := testSettings()
			logger := sett.Logger()

			keys := newTestPrivateKeys(tst.name, logger, tst.privateKeys)
			keys.create(t)
			t.Cleanup(func() {
				keys.cleanup()
			})

			if tst.before != nil {
				tst.before(t, &tst, logger)
			}

			ask := func(promt string) ([]byte, error) {
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
			}

			envsLookup := func(name string) (string, bool) {
				if len(tst.envs) == 0 {
					return "", false
				}
				val, ok := tst.envs[name]
				return val, ok
			}

			parser := NewFlagsParser(sett).
				WithAsk(ask).
				WithEnvsLookup(envsLookup).
				WithEnvsPrefix(tst.envsPrefix)

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
			require.NoError(t, err, "parse flags")

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

type testPrivateKeys struct {
	keys   []*testPrivateKey
	logger log.Logger

	id     string
	tmpDir string
}

func newTestPrivateKeys(name string, logger log.Logger, keys []*testPrivateKey) *testPrivateKeys {
	id := GenerateID(name)
	localTmpDirStr := filepath.Join(os.TempDir(), tmpGlobalDirName, "test-flags", id)

	return &testPrivateKeys{
		keys:   keys,
		logger: logger,
		id:     id,
		tmpDir: localTmpDirStr,
	}
}

func (k *testPrivateKeys) create(t *testing.T) {
	if len(k.keys) == 0 {
		return
	}

	err := os.MkdirAll(k.tmpDir, 0777)
	require.NoError(t, err, "create tmp dir")

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

		path := filepath.Join(k.tmpDir, fmt.Sprintf("id_rsa.%d.%s", i, k.id))
		keyContent := key.content
		if keyContent == "" {
			keyContent = generateKey(t, *password)
		} else {
			k.logger.InfoF("Private key content present for %s Skip generating", path)
		}

		err = os.WriteFile(path, []byte(keyContent), 0600)
		if err != nil {
			k.logger.ErrorF("Cannot write key %s: %v", path, err)
			k.cleanup()
			require.Error(t, err, "write key")
		}
		require.NoError(t, err, "write key %s", path)

		k.logger.InfoF("Private key %s written", path)

		key.path = path
		key.password = password
		key.content = keyContent
		if key.expectedPassword == "" {
			key.expectedPassword = *password
		}
	}
}

func (k *testPrivateKeys) cleanup() {
	tmpDir := k.tmpDir
	if tmpDir == "" || tmpDir == "." || tmpDir == "/" {
		return
	}

	if err := os.RemoveAll(tmpDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		k.logger.ErrorF("Cannot remove test dir '%s': %v", tmpDir, err)
		return
	}

	k.logger.InfoF("Test dir '%s' removed", tmpDir)
}

func stringPtr(s string) *string {
	return &s
}
