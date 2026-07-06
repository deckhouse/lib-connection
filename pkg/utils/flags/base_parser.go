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

package flags

import (
	"context"
	"os"

	"github.com/name212/govalue"

	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/utils/env"
)

type BaseParser struct {
	envsPrefix string
	sett       settings.Settings
	envsLookup env.LookupFunc
}

func NewBaseParser(sett settings.Settings) *BaseParser {
	p := &BaseParser{
		sett:       sett,
		envsLookup: os.LookupEnv,
	}

	p.WithEnvsPrefix(sett.EnvsPrefix())

	return p
}

// WithEnvsPrefix
// This method trim right all _ ang - symbols and spaces left and right
// By default parser add _ after prefix for all env vars
func (p *BaseParser) WithEnvsPrefix(envsPrefix string) {
	p.envsPrefix = env.SimplifyPrefix(envsPrefix)
}

func (p *BaseParser) WithEnvsLookup(lookup env.LookupFunc) {
	if govalue.Nil(lookup) {
		p.sett.Logger().WarnContext(context.Background(), "Envs lookup function is nil. Skip set ask function.")
		return
	}

	p.envsLookup = lookup
}

func (p *BaseParser) Settings() settings.Settings {
	return p.sett
}

func (p *BaseParser) NewEnvsExtractor() *env.Extractor {
	return env.NewExtractor(p.envsPrefix, p.envsLookup)
}
