// Copyright 2025 Flant JSC
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

package gossh

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/deckhouse/lib-connection/pkg/settings"
)

type debugLoggerHandler struct {
	settings settings.Settings

	attrs []slog.Attr
	group string
}

func newDebugLoggerHandler(sett settings.Settings) *debugLoggerHandler {
	return &debugLoggerHandler{
		settings: sett,
	}
}

func newDebugLoggerHandlerWithAttrsAndGroup(parent *debugLoggerHandler, group string, attrs []slog.Attr) *debugLoggerHandler {
	g := parent.group
	if group != "" {
		g = g + "/" + group
	}

	a := make([]slog.Attr, 0, len(parent.attrs))
	a = append(a, parent.attrs...)
	if len(attrs) > 0 {
		a = append(a, attrs...)
	}

	return &debugLoggerHandler{
		settings: parent.settings,
		attrs:    a,
		group:    g,
	}
}

func (h *debugLoggerHandler) Enabled(_ context.Context, lvl slog.Level) bool {
	// handle all
	return true
}

func (h *debugLoggerHandler) Handle(_ context.Context, record slog.Record) error {
	logger := h.settings.Logger()
	write := logger.DebugF
	switch record.Level {
	case slog.LevelDebug:
		write = logger.DebugF
	case slog.LevelInfo:
		write = logger.InfoF
	case slog.LevelWarn:
		write = logger.WarnF
	case slog.LevelError:
		write = logger.ErrorF
	}

	write(h.message(record.Message))

	return nil
}

func (h *debugLoggerHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return newDebugLoggerHandlerWithAttrsAndGroup(h, "", attrs)
}

func (h *debugLoggerHandler) WithGroup(name string) slog.Handler {
	return newDebugLoggerHandlerWithAttrsAndGroup(h, name, nil)
}

func (h *debugLoggerHandler) message(msg string) string {
	totalMsg := strings.Builder{}
	totalMsg.WriteString(`ssh: '`)
	totalMsg.WriteString(msg)
	totalMsg.WriteString(`'`)

	if h.group != "" {
		totalMsg.WriteString(fmt.Sprintf(" group: '%s'", h.group))
	}

	if len(h.attrs) > 0 {
		totalMsg.WriteString(" attributes: [")
		strs := make([]string, 0, len(h.attrs))
		for _, attr := range h.attrs {
			strs = append(strs, attr.String())
		}
		totalMsg.WriteString(strings.Join(strs, " "))
		totalMsg.WriteString("]")
	}

	return totalMsg.String()
}

func debugLogger(sett settings.Settings) *slog.Logger {
	logger := slog.New(newDebugLoggerHandler(sett))
	logger.Enabled(context.TODO(), slog.LevelDebug)
	return logger
}
