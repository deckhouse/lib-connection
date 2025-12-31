// Copyright 2025 Flant JSC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	gossh "github.com/deckhouse/lib-gossh"
	"golang.org/x/crypto/ssh"
)

func GetSSHPrivateKey(keyPath string, passphrase string) (any, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("Reading key file %q got error: %w", keyPath, err)
	}

	keyData = append(bytes.TrimSpace(keyData), '\n')

	var sshKey any

	if len(passphrase) > 0 {
		sshKey, err = gossh.ParseRawPrivateKeyWithPassphrase(keyData, []byte(passphrase))
	} else {
		sshKey, err = gossh.ParseRawPrivateKey(keyData)
	}

	if err != nil {
		var passphraseMissingError *gossh.PassphraseMissingError
		switch {
		case errors.As(err, &passphraseMissingError):
			var err error
			sshKey, err = ssh.ParseRawPrivateKeyWithPassphrase(keyData, []byte(passphrase))
			if err != nil {
				return nil, fmt.Errorf("Wrong passphrase for ssh key")
			}
		default:
			return nil, fmt.Errorf("Parsing private key %q got error: %w", keyPath, err)
		}
	}

	return sshKey, nil
}
