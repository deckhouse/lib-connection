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
	"encoding/json"
	"fmt"

	"github.com/deckhouse/lib-dhctl/pkg/yaml/validation"
	ssh "github.com/deckhouse/lib-gossh"
	"sigs.k8s.io/yaml"
)

var (
	ErrValidationRuleFailed = fmt.Errorf("validation rule failed")
)

func addXRules(validator *validation.Validator) *validation.Validator {
	extsValidator := validation.NewXRulesExtensionsValidator(map[string]validation.ExtensionsValidatorHandler{
		"sshPrivateKey": validateSSHPrivateKey,
		"sshMode":       validateSSHMode,
	})

	validator.AddExtensionsValidators(extsValidator)

	return validator
}

func validateSSHPrivateKey(value json.RawMessage) error {
	var key AgentPrivateKey

	err := yaml.Unmarshal(value, &key)
	if err != nil {
		return err
	}

	privateKeyBytes := []byte(key.Key)

	if key.Passphrase == "" {
		if _, err = ssh.ParseRawPrivateKey(privateKeyBytes); err != nil {
			return validateSSHPrivateKeyErr(err)
		}

		return nil
	}

	if _, err = ssh.ParseRawPrivateKeyWithPassphrase(privateKeyBytes, []byte(key.Passphrase)); err != nil {
		return validateSSHPrivateKeyErr(err)
	}

	return nil
}

func validateSSHPrivateKeyErr(err error) error {
	return fmt.Errorf("%w: invalid ssh key: %w", ErrValidationRuleFailed, err)
}

func validateSSHMode(value json.RawMessage) error {
	var mode Mode

	err := yaml.Unmarshal(value, &mode)
	if err != nil {
		return err
	}

	if mode.LegacyMode && mode.ModernMode {
		return fmt.Errorf("%w: invalid ssh mode: legacyMode and modernMode both true", ErrValidationRuleFailed)
	}

	return nil
}
