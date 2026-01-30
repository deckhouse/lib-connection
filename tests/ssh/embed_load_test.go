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

package ssh

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/deckhouse/lib-connection/pkg/ssh/config"
	"github.com/stretchr/testify/require"
)

func TestEmbedLoadOpenAPISpec(t *testing.T) {
	assertSpec(t, "ssh_host_configuration.yaml", config.HostOpenAPISpec)
	assertSpec(t, "ssh_configuration.yaml", config.ConfigurationOpenAPISpec)
}

func assertSpec(t *testing.T, fileName string, specProvider func() string) {
	actualContent := specProvider()
	require.NotEmpty(t, actualContent, "spec provider should not be empty for file %s", fileName)

	path := filepath.Join("../../pkg/ssh/config/openapi/", fileName)
	fullPath, err := filepath.Abs(path)

	expectedContent, err := os.ReadFile(fullPath)
	require.NoError(t, err, "failed to read host spec file %s; full: %s", fileName, fullPath)

	require.Equal(t, string(expectedContent), actualContent, "expected content does not match for file %s", fileName)
}
