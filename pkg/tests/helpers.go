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

package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/log"
	"github.com/deckhouse/lib-dhctl/pkg/retry"
	gossh "github.com/deckhouse/lib-gossh"
	"github.com/name212/govalue"
	"github.com/stretchr/testify/require"

	"github.com/deckhouse/lib-connection/pkg/settings"
)

const PrivateKeysRoot = "private_keys"

func marshalKey(privateKey *rsa.PrivateKey, passphrase string) (*pem.Block, error) {
	if len(passphrase) == 0 {
		return gossh.MarshalPrivateKey(privateKey, "")
	}

	return gossh.MarshalPrivateKeyWithPassphrase(privateKey, "", []byte(passphrase))
}

func generatePrivateKey(passphrase string) (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("cannot generate key: %w", err)
	}

	publicKey, err := gossh.NewPublicKey(privateKey.Public())
	if err != nil {
		return "", "", fmt.Errorf("cannot create public key from private: %w", err)
	}

	privateKeyPem, err := marshalKey(privateKey, passphrase)
	if err != nil {
		return "", "", fmt.Errorf("cannot marshal private key: %w", err)
	}

	pemBytes := pem.EncodeToMemory(privateKeyPem)

	return string(pemBytes), string(gossh.MarshalAuthorizedKey(publicKey)), nil
}

func GeneratePrivateKeyWithPublic(t *testing.T, passphrase string) (string, string) {
	private, public, err := generatePrivateKey(passphrase)
	require.NoError(t, err, "cannot generate private key")

	return strings.TrimRight(private, "\n"), public
}

func GeneratePrivateKey(t *testing.T, passphrase string) string {
	private, _ := GeneratePrivateKeyWithPublic(t, passphrase)
	return private
}

// helper func to generate SSH keys
func GenerateKeys(test *Test, passphrase string) (string, string, error) {
	private, public, err := generatePrivateKey(passphrase)
	if err != nil {
		return "", "", err
	}

	privateKeyPath, err := test.CreateTmpFile(private, false, PrivateKeysRoot, "id_rsa")
	if err != nil {
		return "", "", fmt.Errorf("cannot write private key: %w", err)
	}

	if err := os.Chmod(privateKeyPath, 0600); err != nil {
		return "", "", fmt.Errorf("cannot chmod to 600 private key file: %w", err)
	}

	return privateKeyPath, public, nil
}

func WritePubKeyFileForPrivate(test *Test, privateKeyPath string, pubKey string) (string, error) {
	return test.CreateFileWithSameSuffix(privateKeyPath, pubKey, false, PrivateKeysRoot, "id_rsa.pub")
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

func PrepareFakeBashibleBundle(t *testing.T, test *Test, entrypoint, bundleDir string) string {
	bundleDirPath := func() []string {
		return []string{"bundle_test", bundleDir}
	}

	parentDir := test.MustMkSubDirs(t, bundleDirPath()...)

	entrypointScript := `#!/bin/bash

echo "starting execute steps..."

BUNDLE_STEPS_DIR=/var/lib/bashible/bundle_steps
BOOTSTRAP_DIR=/var/lib/bashible
MAX_RETRIES=5

for arg in "$@"; do
  if [[ "$arg" == "--add-failure" ]]
    then
      echo "failures included"
      export INCLUDE_FAILURE=true
  fi
done

# Execute bashible steps
for step in $BUNDLE_STEPS_DIR/*; do
  echo ===
  echo === Step: $step
  echo ===
  attempt=0
  sx=""
  until /bin/bash --noprofile --norc -"$sx"eEo pipefail -c "export TERM=xterm-256color; unset CDPATH; cd $BOOTSTRAP_DIR; source $step" 2> >(tee /var/lib/bashible/step.log >&2)
  do
    attempt=$(( attempt + 1 ))
    if [ -n "${MAX_RETRIES-}" ] && [ "$attempt" -gt "${MAX_RETRIES}" ]; then
      >&2 echo "ERROR: Failed to execute step $step. Retry limit is over."
      exit 1
    fi
    >&2 echo "Failed to execute step "$step" ... retry in 10 seconds."
    sleep 10
    echo ===
    echo === Step: $step
    echo ===
    if [ "$attempt" -gt 2 ]; then
      sx=x
    fi
  done
done

`

	entrypointPath := append(bundleDirPath(), entrypoint)
	test.MustCreateFile(t, entrypointScript, true, entrypointPath...)

	scrips := []struct {
		name    string
		content string
	}{
		{
			name: "01-step.sh",
			content: `#!/bin/bash
echo "just a step"

for i in {0..3}
do
  sleep $(( $RANDOM % 2 ))
  echo $i  
done
`,
		},
		{
			name: "02-step.sh",
			content: `#!/bin/bash

echo "second step"

for i in {0..4}
do
  sleep $(( $RANDOM % 2 ))
  echo $i
  if [[ $i -gt 2 && $INCLUDE_FAILURE == "true" ]]
    then
      echo "oops! failure!"
      exit 1
  fi
done
`,
		},
	}

	for _, c := range scrips {
		scriptPath := append(bundleDirPath(), "bundle_steps", c.name)
		test.MustCreateFile(t, c.content, true, scriptPath...)
	}

	return filepath.Dir(parentDir)
}

func SetEnvs(t *testing.T, envs map[string]string) {
	if len(envs) == 0 {
		return
	}

	forUnset := make(map[string]struct{})
	oldEnvs := make(map[string]string)

	t.Cleanup(func() {
		for k, v := range oldEnvs {
			if err := os.Setenv(k, v); err != nil {
				t.Logf("error restore env variable %s: %v", k, err)
			}
		}

		for k := range forUnset {
			if err := os.Unsetenv(k); err != nil {
				t.Logf("error unset env variable %s: %v", k, err)
			}
		}
	})

	for k, v := range envs {
		old, ok := os.LookupEnv(k)
		if ok {
			oldEnvs[k] = old
		}

		if err := os.Setenv(k, v); err != nil {
			require.NoError(t, err, "error set env variable %s", k)
		}

		if !ok {
			forUnset[k] = struct{}{}
		}
	}
}

func Ptr[T any](v T) *T {
	return &v
}

var forReplace = []string{" ", ",", ".", "-"}

func prepareTestNames(names ...string) string {
	l := len(names)
	if l == 0 {
		return ""
	}

	tests := make([]string, 0, l)
	for _, name := range names {
		for _, old := range forReplace {
			name = strings.ReplaceAll(name, old, "_")
		}
		tests = append(tests, name)
	}

	return strings.Join(tests, "/")
}

func Name(t *testing.T) string {
	return prepareTestNames(t.Name())
}

func findLogMsg(t *testing.T, sett settings.Settings, msgInLog string) string {
	loggerInterface := sett.Logger()

	logger, ok := loggerInterface.(*log.InMemoryLogger)
	require.True(t, ok, "logger is not of type *log.InMemoryLogger")

	getMatch, err := logger.FirstMatch(&log.Match{
		Prefix: []string{
			msgInLog,
		},
	})

	require.NoError(t, err, "failed to find match in log")

	return getMatch
}

func AssertLogMessage(t *testing.T, sett settings.Settings, msgInLog string) {
	getMatch := findLogMsg(t, sett, msgInLog)
	require.Contains(t, getMatch, msgInLog, "should contain %s", msgInLog)
}

func AssertNoLogMessage(t *testing.T, sett settings.Settings, msgInLog string) {
	getMatch := findLogMsg(t, sett, msgInLog)
	require.Empty(t, getMatch, "should not find log msg %s", msgInLog)
}
