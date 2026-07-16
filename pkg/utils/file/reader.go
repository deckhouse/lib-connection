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
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/deckhouse/lib-connection/pkg/utils/defaults"
	"github.com/deckhouse/lib-connection/pkg/utils/env"
)

func Reader(path string, fileType string) (io.ReadCloser, error) {
	r, _, err := getReader(path, fileType)
	return r, err
}

func ReadFile(ctx context.Context, path string, fileType string, logger ...*slog.Logger) ([]byte, string, error) {
	reader, fullPath, err := getReader(path, fileType)
	if err != nil {
		return nil, "", err
	}

	defer func() {
		err := reader.Close()
		if err != nil && len(logger) > 0 {
			logger[0].DebugContext(ctx, fmt.Sprintf("Error closing config file: %v", err))
		}
	}()

	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, "", err
	}

	return content, fullPath, nil
}

func IsExists(path string, fileType string) error {
	_, err := isExists(path, fileType, false)
	return err
}

func isExists(path string, fileType string, shouldRegular bool) (string, error) {
	fullPath, err := FullPath(path, fileType)
	if err != nil {
		return "", err
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

func FullPath(path string, fileType string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("pass empty path for %s", fileType)
	}

	fullPath, err := resolveTilda(path, fileType)
	if err != nil {
		return fullPath, err
	}

	fullPath, err = filepath.Abs(fullPath)
	if err != nil {
		return fullPath, fmt.Errorf("cannot get abs path for %s for type %s: %w", path, fileType, err)
	}

	return fullPath, nil
}

func getReader(path string, fileType string) (io.ReadCloser, string, error) {
	fullPath, err := isExists(path, fileType, true)
	if err != nil {
		return nil, "", err
	}

	r, err := os.Open(fullPath)
	if err != nil {
		return nil, "", err
	}

	return r, fullPath, nil
}

func resolveTilda(path string, fileType string) (string, error) {
	if !strings.HasPrefix(path, "~") {
		return path, nil
	}

	extractor := env.NewOsExtractor("")
	home, err := defaults.HomeDir(extractor)
	if err != nil {
		return "", fmt.Errorf("path %s for %s contains ~ cannot resolve it: %w", path, fileType, err)
	}

	return filepath.Join(home, path[1:]), nil
}
