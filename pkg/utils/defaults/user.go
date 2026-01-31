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

package defaults

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/deckhouse/lib-connection/pkg/utils/env"
)

// HomeDir
// extract absolute user home dir in next order
// HOME env
// os.UserHomeDir
// also check that HOME is present and is dir
func HomeDir(extractor *env.Extractor) (string, error) {
	home := ""

	extractor.StringWithoutPrefix("HOME", &home)

	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("Cannot get user home dir: %w", err)
		}

		if home == "" {
			return "", fmt.Errorf("Cannot get user home dir: empty after call os.UserHomeDir")
		}
	}

	var err error
	home, err = filepath.Abs(home)
	if err != nil {
		return "", fmt.Errorf("Cannot get absolute path of home directory: %w", err)
	}

	stat, err := os.Stat(home)
	if err != nil {
		return "", fmt.Errorf("Cannot get user home dir stat: %w", err)
	}

	if !stat.IsDir() {
		return "", fmt.Errorf("Cannot get user home dir: '%s' not a directory", home)
	}

	return home, nil
}

// CurrentUserName
// returns current username
// first attempt get user from env
// can be call multiple times because user.Current() cache user info
func CurrentUserName(extractor *env.Extractor) (string, error) {
	userName := ""

	extractor.StringWithoutPrefix("USER", &userName)

	if userName != "" {
		return userName, nil
	}

	currentUser, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("cannot get current user: %w", err)
	}

	userName = currentUser.Username
	if userName == "" {
		return "", fmt.Errorf("Cannot get current user: empty after call user.Current")
	}

	return userName, nil
}
