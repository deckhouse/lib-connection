// Copyright 2025 Flant JSC
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

package ssh_testing

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/log"
	"github.com/deckhouse/lib-dhctl/pkg/retry"
	gossh "github.com/deckhouse/lib-gossh"
	"github.com/name212/govalue"
	"github.com/stretchr/testify/require"
)

const PrivateKeysRoot = "private_keys"

// helper func to generate SSH keys
func GenerateKeys(test *Test, passphrase string) (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	var privateKeyPem *pem.Block
	if len(passphrase) == 0 {
		privateKeyPem, err = gossh.MarshalPrivateKey(privateKey, "")
		if err != nil {
			return "", "", err
		}
	} else {
		privateKeyPem, err = gossh.MarshalPrivateKeyWithPassphrase(privateKey, "", []byte(passphrase))
		if err != nil {
			return "", "", err
		}
	}

	publicKey, err := gossh.NewPublicKey(privateKey.Public())
	if err != nil {
		return "", "", err
	}

	pemBytes := pem.EncodeToMemory(privateKeyPem)

	privateKeyPath, err := test.CreateTmpFile(string(pemBytes), false, PrivateKeysRoot, "id_rsa")
	if err != nil {
		return "", "", err
	}

	return privateKeyPath, string(gossh.MarshalAuthorizedKey(publicKey)), nil
}

func LogErrorOrAssert(t *testing.T, description string, err error, logger log.Logger) {
	if err == nil {
		return
	}

	if govalue.Nil(logger) {
		require.NoError(t, err, description)
		return
	}

	logger.ErrorF("%s: %v", description, err)
}

func StopContainerAndRemoveKeys(t *testing.T, container *SSHContainer, logger log.Logger, keyPaths ...string) {
	var containerStopError, removeSSHDConfigError error
	if !govalue.Nil(container) {
		containerStopError = container.Stop()
		removeSSHDConfigError = container.RemoveSSHDConfig()
	}

	removeErrors := removeFiles(keyPaths...)

	LogErrorOrAssert(t, "failed to stop container", containerStopError, logger)
	LogErrorOrAssert(t, "remove sshd config", removeSSHDConfigError, logger)
	for _, removeError := range removeErrors {
		LogErrorOrAssert(t, "failed to remove private key", removeError, logger)
	}
}

func RemoveFiles(t *testing.T, logger log.Logger, paths ...string) {
	removeErrors := removeFiles(paths...)

	for _, removeError := range removeErrors {
		LogErrorOrAssert(t, "failed to remove private key", removeError, logger)
	}
}

func CheckSkipSSHTest(t *testing.T, testName string) {
	if os.Getenv("SKIP_GOSSH_TEST") == "true" {
		t.Skipf("Skipping %s test. SKIP_GOSSH_TEST=true env passed", testName)
	}
}

func GetTestLoopParamsForFailed() retry.Params {
	return retry.NewEmptyParams(
		retry.WithWait(2*time.Second),
		retry.WithAttempts(4),
	)
}

func IncorrectHost() string {
	third := RandRange(1, 254)
	four := RandRange(1, 254)
	return fmt.Sprintf("192.168.%d.%d", third, four)
}

func Sleep(d time.Duration) {
	if d > 0 {
		time.Sleep(d)
	}
}

func removeFiles(paths ...string) []error {
	removeErrors := make([]error, 0, len(paths))
	for _, path := range paths {
		if path == "" {
			continue
		}

		stat, err := os.Stat(path)
		if err != nil {
			if !os.IsNotExist(err) {
				removeErrors = append(removeErrors, fmt.Errorf("cannot stat %s: %w", path, err))
			}
			continue
		}

		remove := os.Remove
		if stat.IsDir() {
			remove = os.RemoveAll
		}

		if err := remove(path); err != nil && !os.IsNotExist(err) {
			removeErrors = append(removeErrors, err)
		}
	}

	return removeErrors
}
