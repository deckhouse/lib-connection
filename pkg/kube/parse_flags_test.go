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

package kube

import (
	"testing"

	flag "github.com/spf13/pflag"

	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/tests"
)

func TestParseFlagsHelp(t *testing.T) {
	tests.AssertParseFlagsHelp(t, tests.AssertParseFlagsHelpParams{
		ExpectedFlags: 3,
		Name:          "kube-flags",
		Provider: func(sett settings.Settings, envsPrefix string) tests.TestFlagsParser {
			parser := NewFlagsParser(sett)
			parser.WithEnvsPrefix(envsPrefix)

			return &testHelpParser{parser: parser}
		},
	})
}

type testHelpParser struct {
	parser *FlagsParser
}

func (p *testHelpParser) InitFlags(flagSet *flag.FlagSet) error {
	_, err := p.parser.InitFlags(flagSet)
	return err
}
