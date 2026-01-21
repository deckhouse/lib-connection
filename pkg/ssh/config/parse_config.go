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
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/deckhouse/lib-dhctl/pkg/log"
	"github.com/deckhouse/lib-dhctl/pkg/yaml"
	"github.com/deckhouse/lib-dhctl/pkg/yaml/validation"
	yamlk8s "sigs.k8s.io/yaml"

	"github.com/deckhouse/lib-connection/pkg/settings"
)

const (
	sshConfigKind = "SSHConfig"
	sshHostKind   = "SSHHost"
)

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

	docs := yaml.SplitYAMLBytes(configData)

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
			errs.appendValidation(err, index, i)
			continue
		}

		switch index.Kind {
		case sshConfigKind:
			connectionConfigDocsCount++
			sshConfig := Config{}
			err := yamlk8s.Unmarshal(docData, &sshConfig)
			if err != nil {
				errs.appendUnmarshalError(err, index, i)
				continue
			}
			config.Config = &sshConfig
			logger.DebugF("SSHConfig added in result config")
		case sshHostKind:
			sshHostConfigDocsCount++
			sshHost := Host{}
			err := yamlk8s.Unmarshal(docData, &sshHost)
			if err != nil {
				errs.appendUnmarshalError(err, index, i)
				continue
			}

			config.Hosts = append(config.Hosts, sshHost)
			logger.DebugF("SSHHost '%s' added in result config, host in result config %d", sshHost.Host, len(config.Hosts))
		default:
			errs.appendUnknownKind(index, i)
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

	validateOnlyUniqueHosts(config, errs)

	if err := errs.ErrorOrNil(); err != nil {
		return nil, err
	}

	return config, nil
}

func validateOnlyUniqueHosts(cfg *ConnectionConfig, errs *parseErrors) {
	if len(cfg.Hosts) == 0 {
		return
	}

	hostsCounts := make(map[string]int)

	for _, host := range cfg.Hosts {
		hostsCounts[host.Host]++
	}

	for host, count := range hostsCounts {
		if count > 1 {
			errs.appendMultipleHost(host, count)
		}
	}
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

func (e *parseErrors) appendMultipleHost(host string, count int) {
	e.Append(validation.ErrDocumentValidationFailed, validation.Error{
		Messages: []string{
			fmt.Sprintf("host '%s' present multiple times %d", host, count),
		},
	})
}

func (e *parseErrors) appendValidation(err error, index *validation.SchemaIndex, i int) {
	if errors.Is(err, validation.ErrSchemaNotFound) {
		e.appendUnknownKind(index, i)
		return
	}

	e.appendError(err, i, "")
}

func (e *parseErrors) appendUnknownKind(index *validation.SchemaIndex, i int) {
	e.appendError(
		validation.ErrKindValidationFailed,
		i,
		"Unknown kind: %s, expected one of (%q, %q)", index.String(), sshConfigKind, sshHostKind,
	)
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
