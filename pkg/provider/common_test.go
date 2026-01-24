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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/log"
	gossh "github.com/deckhouse/lib-gossh"
	"github.com/stretchr/testify/require"

	"github.com/deckhouse/lib-connection/pkg/settings"
)

func testSettings(t *testing.T) settings.Settings {
	const isDebug = true

	logger := log.NewInMemoryLoggerWithParent(
		log.NewPrettyLogger(log.LoggerOptions{IsDebug: isDebug}),
	)

	name := t.Name()
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, ":", "_")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ToLower(name)

	logger.InfoF("Got name: %s", name)

	id := GenerateID(name)

	localTmpDirStr := filepath.Join(os.TempDir(), tmpGlobalDirName, "test-ssh-provider", id)
	err := os.MkdirAll(localTmpDirStr, 0755)
	require.NoError(t, err, "failed to create tmp dir")

	logger.InfoF("Created tmp dir %s", localTmpDirStr)

	t.Cleanup(func() {
		if err := os.RemoveAll(localTmpDirStr); err != nil {
			logger.ErrorF("Failed to remove tmp dir '%s': %v", localTmpDirStr, err)
			return
		}

		logger.InfoF("Tmp dir '%s' removed", localTmpDirStr)
	})

	return settings.NewBaseProviders(settings.ProviderParams{
		LoggerProvider: log.SimpleLoggerProvider(logger),
		IsDebug:        isDebug,
		TmpDir:         localTmpDirStr,
		EnvsPrefix:     "TEST_SSH_PROVIDER",
	})
}

func assertLogMessage(t *testing.T, sett settings.Settings, msgInLog string) {
	loggerInterface := sett.Logger()

	logger, ok := loggerInterface.(*log.InMemoryLogger)
	require.True(t, ok, "logger is not of type *log.InMemoryLogger")

	getMatch, err := logger.FirstMatch(&log.Match{
		Prefix: []string{
			msgInLog,
		},
	})

	require.NoError(t, err, "failed to find match in log")
	require.Contains(t, getMatch, msgInLog, "should contain %s", msgInLog)
}

// TODO move to test helpers packet
const (
	tmpGlobalDirName = "test-lib-connection"
)

var (
	lettersRunes  = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	passwordRunes = append(
		append([]rune{}, lettersRunes...),
		[]rune(" %!@#$&^*.,/")...,
	)
)

func GenerateID(names ...string) string {
	if len(names) == 0 {
		names = make([]string, 0, 1)
	}

	names = append(names, randTestString(12, lettersRunes))
	sumString := strings.Join(names, "/")
	sum := sha256Encode(sumString)

	return fmt.Sprintf("%.12s", sum)
}

func RandPassword(n int) string {
	return randTestString(n, passwordRunes)
}

func randTestString(n int, letters []rune) string {
	randomizer := getRand()

	b := make([]rune, n)
	for i := range b {
		b[i] = letters[randomizer.Intn(len(letters))]
	}

	return string(b)
}

func getRand() *mathrand.Rand {
	return mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
}

func sha256Encode(input string) string {
	hasher := sha256.New()

	hasher.Write([]byte(input))

	return fmt.Sprintf("%x", hasher.Sum(nil))
}

func marshalKey(privateKey *rsa.PrivateKey, passphrase string) (*pem.Block, error) {
	if len(passphrase) == 0 {
		return gossh.MarshalPrivateKey(privateKey, "")
	}

	return gossh.MarshalPrivateKeyWithPassphrase(privateKey, "", []byte(passphrase))
}

// helper func to generate SSH keys
func generateKey(t *testing.T, passphrase string) string {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "error generating rsa key")

	privateKeyPem, err := marshalKey(privateKey, passphrase)
	require.NoError(t, err, "error marshaling rsa key")

	pemBytes := pem.EncodeToMemory(privateKeyPem)

	return strings.TrimRight(string(pemBytes), "\n")
}
