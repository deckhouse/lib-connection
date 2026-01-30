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

package tests

import (
	"fmt"

	"github.com/deckhouse/lib-dhctl/pkg/log"
)

type PrefixLogger struct {
	log.Logger
	prefix  string
	address string
}

func newPrefixLoggerWithAddress(logger log.Logger, address string) *PrefixLogger {
	l := NewPrefixLogger(logger)
	l.address = address
	return l.WithPrefix("")
}

func NewPrefixLogger(logger log.Logger) *PrefixLogger {
	l := &PrefixLogger{
		Logger: logger,
	}

	return l.WithPrefix("")
}

func (l *PrefixLogger) Log(write func(string, ...any), f string, args ...any) {
	if l.prefix != "" {
		f = l.prefix + ": " + f
	}

	write(f, args...)
}

func (l *PrefixLogger) Error(f string, args ...any) {
	l.Log(l.ErrorF, f, args...)
}

func (l *PrefixLogger) Info(f string, args ...any) {
	l.Log(l.InfoF, f, args...)
}

func (l *PrefixLogger) WithPrefix(p string) *PrefixLogger {
	if l.address != "" {
		p = fmt.Sprintf("%s (%s)", p, l.address)
	}

	l.prefix = p
	return l
}
