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

package terminal

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	dhlog "github.com/deckhouse/lib-dhctl/pkg/logger"
	terminal "golang.org/x/term"
)

func AskPassword(logger *slog.Logger, prompt string) ([]byte, error) {
	fd := int(os.Stdin.Fd())

	if !terminal.IsTerminal(fd) {
		return nil, fmt.Errorf("stdin is not a terminal, cannot read password")
	}

	ctx := context.Background()
	logger.InfoContext(ctx, prompt, dhlog.ShowInCompacted())
	data, err := terminal.ReadPassword(fd)
	logger.InfoContext(ctx, fmt.Sprint(), dhlog.ShowInCompacted())

	if err != nil {
		return nil, fmt.Errorf("read secret: %w", err)
	}

	return data, nil
}
