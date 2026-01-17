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
	"io"
	"strings"

	"github.com/deckhouse/lib-dhctl/pkg/log"
	"github.com/deckhouse/lib-dhctl/pkg/yaml"
	"github.com/deckhouse/lib-dhctl/pkg/yaml/validation"

	"github.com/deckhouse/lib-connection/pkg/settings"
)

const (
	sshConfigKind = "SSHConfig"
	sshHostKind   = "SSHHost"
)

type validateOptions struct {
	omitDocInError  bool
	strictUnmarshal bool
	requiredSSHHost bool
	noPrettyError   bool
}

type ValidateOption func(o *validateOptions)

func ParseWithOmitDocInError(v bool) ValidateOption {
	return func(o *validateOptions) {
		o.omitDocInError = v
	}
}

func ParseWithStrictUnmarshal(v bool) ValidateOption {
	return func(o *validateOptions) {
		o.strictUnmarshal = v
	}
}

func ParseWithRequiredSSHHost(v bool) ValidateOption {
	return func(o *validateOptions) {
		o.requiredSSHHost = v
	}
}

func ParseWithNoPrettyError(v bool) ValidateOption {
	return func(o *validateOptions) {
		o.noPrettyError = v
	}
}

func ParseConnectionConfig(reader io.Reader, sett settings.Settings, opts ...ValidateOption) (*ConnectionConfig, error) {
	options := &validateOptions{
		requiredSSHHost: true,
		strictUnmarshal: true,
	}
	for _, o := range opts {
		o(options)
	}

	configData, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	docs := yaml.SplitYAML(string(configData))

	errs := newParseErrors()

	logger := sett.Logger()
	logger.DebugF("Parsing connection config has %d documents", len(docs))

	validator := getValidator(sett.LoggerProvider())
	validatorOpts := parseOptionsToValidatorOpts(options)

	config := &ConnectionConfig{}
	var connectionConfigDocsCount int
	var sshHostConfigDocsCount int

	for i, doc := range docs {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			logger.DebugF("Skip empty document %d", i)
			continue
		}

		docData := []byte(doc)

		index, err := validation.ParseIndex(strings.NewReader(doc))
		if err != nil {
			errs.appendError(err, i, "Extract index from document")
			continue
		}

		logger.DebugF("Process validate and parse connection config document %d for index %v", i, index)

		err = validator.ValidateWithIndex(index, &docData, validatorOpts...)
		if err != nil {
			// no message error, err contains all information
			errs.appendError(err, i, "")
			continue
		}

		switch index.Kind {
		case sshConfigKind:
			connectionConfigDocsCount++
			sshConfig, err := yaml.Unmarshal[Config](docData)
			if err != nil {
				errs.appendUnmarshalError(err, index, i)
				continue
			}
			config.Config = &sshConfig
			logger.DebugF("SSHConfig added in result config")
		case sshHostKind:
			sshHostConfigDocsCount++
			sshHost, err := yaml.Unmarshal[Host](docData)
			if err != nil {
				errs.appendUnmarshalError(err, index, i)
				continue
			}

			config.Hosts = append(config.Hosts, sshHost)
			logger.DebugF("SSHHost '%s' added in result config, host in result config %d", sshHost.Host, len(config.Hosts))
		default:
			errs.appendError(
				validation.ErrKindValidationFailed,
				i,
				"Unknown kind, expected one of (%q, %q)", sshConfigKind, sshHostKind,
			)
			continue
		}
	}

	if err := errs.ErrorOrNil(); err != nil {
		return nil, err
	}

	if connectionConfigDocsCount != 1 {
		errs.appendError(
			validation.ErrKindValidationFailed,
			0,
			"exactly one %q required", sshConfigKind,
		)
	}

	if options.requiredSSHHost && sshHostConfigDocsCount == 0 {
		errs.appendError(
			validation.ErrKindValidationFailed,
			0,
			"at least one %q required", sshHostKind,
		)
	}

	return config, nil
}

func getValidator(logger log.LoggerProvider) *validation.Validator {
	validator := validation.NewValidatorWithLogger(specsForValidator, logger)
	return addXRules(validator)
}

func parseOptionsToValidatorOpts(o *validateOptions) []validation.ValidateOption {
	return []validation.ValidateOption{
		validation.ValidateWithOmitDocInError(o.omitDocInError),
		validation.ValidateWithStrictUnmarshal(o.strictUnmarshal),
		validation.ValidateWithNoPrettyError(o.noPrettyError),
	}
}

type parseErrors struct {
	*validation.ValidationError
}

func newParseErrors() *parseErrors {
	return &parseErrors{
		ValidationError: &validation.ValidationError{},
	}
}

func (e *parseErrors) appendError(err error, index int, msgFormat string, args ...interface{}) {
	msg := fmt.Sprintf(msgFormat, args...)
	if msg != "" {
		msg = fmt.Sprintf("%s: %v", msg, err)
	} else {
		msg = err.Error()
	}

	toAppend := validation.Error{
		Messages: []string{msg},
	}

	if index > 0 {
		toAppend.Index = &index
	}

	validationError := validation.ExtractValidationError(err)
	e.Append(validationError, toAppend)
}

func (e *parseErrors) appendUnmarshalError(err error, schemaIndex *validation.SchemaIndex, docIndex int) {
	kind := schemaIndex.Kind
	group, groupVersion := schemaIndex.GroupAndGroupVersion()

	e.Append(validation.ErrKindValidationFailed, validation.Error{
		Index: &docIndex,
		Messages: []string{
			fmt.Sprintf("Cannot unmarshal to %s document %d: %v", kind, docIndex, err),
		},
		Kind:    kind,
		Version: groupVersion,
		Group:   group,
	})
}
