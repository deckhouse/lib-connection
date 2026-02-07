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
	fullPath, err := isExists(path, fileType, true)
	if err != nil {
		return nil, err
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

func IsExists(path string, fileType string) error {
	_, err := isExists(path, fileType, false)
	return err
}

func isExists(path string, fileType string, shouldRegular bool) (string, error) {
	if path == "" {
		return "", fmt.Errorf("pass empty path for %s", fileType)
	}

	fullPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("cannot get abs path for %s: %w", path, err)
	}

	stat, err := os.Stat(fullPath)
	if err != nil {
		return "", fmt.Errorf("cannot get %s file info for %s: %w", fileType, fullPath, err)
	}

	if stat.IsDir() {
		return "", fmt.Errorf("%s path '%s' should be a file not dir", fileType, fullPath)
	}

	if shouldRegular && !stat.Mode().IsRegular() {
		return "", fmt.Errorf("%s path '%s' should be regular file", fileType, fullPath)
	}

	return fullPath, nil
}
