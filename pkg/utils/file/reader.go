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

package file

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/deckhouse/lib-dhctl/pkg/log"
)

func Reader(path string, fileType string) (io.ReadCloser, error) {
	fullPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("Cannot get abs path for %s: %w", path, err)
	}

	stat, err := os.Stat(fullPath)
	if err != nil {
		return nil, fmt.Errorf("Cannot get %s file info for %s: %w", fileType, fullPath, err)
	}

	if stat.IsDir() || !stat.Mode().IsRegular() {
		return nil, fmt.Errorf("%s path '%s' should be regular file", fileType, fullPath)
	}

	return os.Open(fullPath)
}

func ReadFile(path string, fileType string, logger ...log.Logger) ([]byte, error) {
	reader, err := Reader(path, fileType)
	if err != nil {
		return nil, err
	}

	defer func() {
		err := reader.Close()
		if err != nil && len(logger) > 0 {
			logger[0].DebugF("Error closing config file: %v", err)
		}
	}()

	return io.ReadAll(reader)
}
