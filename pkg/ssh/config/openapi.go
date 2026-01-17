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
	_ "embed"
	"fmt"
	"strings"

	"github.com/deckhouse/lib-dhctl/pkg/yaml/validation"
	"github.com/go-openapi/spec"
)

var (
	//go:embed openapi/ssh_configuration.yaml
	configurationOpenAPISpecContent string

	//go:embed openapi/ssh_host_configuration.yaml
	hostOpenAPISpecContent string

	specsForValidator = make(map[validation.SchemaIndex]*spec.Schema)
)

func init() {
	var err error
	specsForValidator, err = loadSpecs()
	if err != nil {
		panic(err)
	}
}

func ConfigurationOpenAPISpec() string {
	return configurationOpenAPISpecContent
}

func HostOpenAPISpec() string {
	return hostOpenAPISpecContent
}

func loadSpecs() (map[validation.SchemaIndex]*spec.Schema, error) {
	configurationSpecs, err := validation.LoadSchemas(strings.NewReader(configurationOpenAPISpecContent))
	if err != nil {
		return nil, fmt.Errorf("error loading ssh connection configuration schema: %v", err)
	}

	hostSpec, err := validation.LoadSchemas(strings.NewReader(hostOpenAPISpecContent))
	if err != nil {
		return nil, fmt.Errorf("error loading ssh host configuration schema: %v", err)
	}

	if len(configurationSpecs) == 0 {
		return nil, fmt.Errorf("error loading ssh host configuration schema: no specs found")
	}

	if len(hostSpec) == 0 {
		return nil, fmt.Errorf("error loading ssh host configuration schema: no specs found")
	}

	res := make(map[validation.SchemaIndex]*spec.Schema, len(configurationSpecs)+len(hostSpec))

	for _, s := range configurationSpecs {
		res[s.Index] = s.Schema
	}

	for _, s := range hostSpec {
		res[s.Index] = s.Schema
	}

	return res, nil
}
