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

	"github.com/deckhouse/lib-dhctl/pkg/log"
	ssh "github.com/deckhouse/lib-gossh"

	"github.com/deckhouse/lib-connection/pkg/ssh/utils/terminal"
)

type PassphraseConsumer interface {
	DefaultPassword() []byte
	AskPassword(prompt string) ([]byte, error)
}

type baseConsumer struct {
	defaultPassword []byte
}

func (c *baseConsumer) DefaultPassword() []byte {
	return c.defaultPassword
}

type TerminalPassphraseConsumer struct {
	*baseConsumer
	logger log.Logger
}

func NewTerminalPassphraseConsumer(logger log.Logger, defaultPassword []byte) *TerminalPassphraseConsumer {
	return &TerminalPassphraseConsumer{
		baseConsumer: &baseConsumer{
			defaultPassword: defaultPassword,
		},
		logger: logger,
	}
}

func (c *TerminalPassphraseConsumer) AskPassword(prompt string) ([]byte, error) {
	return terminal.AskPassword(c.logger, prompt)
}

type DefaultPassphraseOnlyConsumer struct {
	*baseConsumer
}

func NewDefaultPassphraseOnlyConsumer(defaultPassword string) *DefaultPassphraseOnlyConsumer {
	return &DefaultPassphraseOnlyConsumer{
		baseConsumer: &baseConsumer{
			defaultPassword: []byte(defaultPassword),
		},
	}
}

func (c *DefaultPassphraseOnlyConsumer) AskPassword(prompt string) ([]byte, error) {
	return nil, fmt.Errorf("%s. AskPassword not allow for DefaultPassphraseOnlyConsumer", prompt)
}

func ParseSSHPrivateKeyFile(path string, password string, logger log.Logger) (any, string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("Cannot read private key file %s: %w", path, err)
	}

	return ParseSSHPrivateKey(
		content,
		path,
		NewTerminalPassphraseConsumer(
			logger,
			[]byte(password),
		),
	)
}

func ParseSSHPrivateKey(keyData []byte, keyName string, passphraseConsumer PassphraseConsumer) (any, string, error) {
	keyData = append(bytes.TrimSpace(keyData), '\n')

	var sshKey any

	askPrompt := fmt.Sprintf("Enter passphrase for ssh key %q: ", keyName)

	passphrase := passphraseConsumer.DefaultPassword()

	var err error
	if len(passphrase) > 0 {
		sshKey, err = ssh.ParseRawPrivateKeyWithPassphrase(keyData, passphrase)
	} else {
		sshKey, err = ssh.ParseRawPrivateKey(keyData)
	}

	if err != nil {
		var passphraseMissingError *ssh.PassphraseMissingError
		switch {
		case errors.As(err, &passphraseMissingError):
			var err error
			if passphrase, err = passphraseConsumer.AskPassword(askPrompt); err != nil {
				return nil, "", err
			}
			sshKey, err = ssh.ParseRawPrivateKeyWithPassphrase(keyData, passphrase)
			if err != nil {
				return nil, "", fmt.Errorf("Wrong passphrase for ssh key")
			}
		default:
			return nil, "", fmt.Errorf("Parsing private key %q got error: %w", keyName, err)
		}
	}

	return sshKey, string(passphrase), nil
}
