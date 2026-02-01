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
	"testing"

	flag "github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/deckhouse/lib-connection/pkg/utils/env"
)

func TestBaseFlagsParse(t *testing.T) {
	type parseParam struct {
		shouldParsed   bool
		opts           []BaseFlagsOpt
		additionalArgs []string
	}

	getSet := func(res *string, opts ...BaseFlagsOpt) (*flag.FlagSet, *BaseFlags) {
		fset := flag.NewFlagSet("test", flag.ContinueOnError)
		fset.StringVar(res, "arg", "", "test arg")
		return fset, NewBaseFlags(fset, env.NewOsExtractor(""), opts...)
	}

	assertParse := func(t *testing.T, params parseParam) (*flag.FlagSet, *BaseFlags) {
		args := append([]string{}, params.additionalArgs...)
		args = append(args, "--arg=value")

		res := ""

		fset, base := getSet(&res, params.opts...)

		err := base.Parse(args)
		if !params.shouldParsed {
			require.Error(t, err, "should not parse")
			return fset, base
		}

		require.NoError(t, err, "should parsed")
		require.Equal(t, res, "value", "should set arg")

		return fset, base
	}

	t.Run("should copy flags", func(t *testing.T) {
		fset, base := assertParse(t, parseParam{
			shouldParsed: true,
		})

		require.False(t, fset.Parsed(), "should not parse input flags set")
		require.True(t, base.FlagSet().Parsed(), "should parse flags set copy in base")
	})

	type unknownTest struct {
		name         string
		opts         []BaseFlagsOpt
		shouldParsed bool
	}

	unknownTests := []unknownTest{
		{
			name: "should parse flags if allow unknown",
			opts: []BaseFlagsOpt{
				BaseFlagsSkipUnknownFlags(),
			},
			shouldParsed: true,
		},

		{
			name:         "should not parse flags if disallow unknown",
			opts:         nil,
			shouldParsed: false,
		},
	}

	for _, ts := range unknownTests {
		t.Run(ts.name, func(t *testing.T) {
			assertParse(t, parseParam{
				shouldParsed:   ts.shouldParsed,
				opts:           ts.opts,
				additionalArgs: []string{"--unknown=val"},
			})
		})
	}

	t.Run("not parse if not initialized", func(t *testing.T) {
		assertParseNils := func(t *testing.T, flags *BaseFlags) {
			parse := func() {
				err := flags.Parse([]string{"--arg=value"})
				require.Error(t, err, "should not parse nil base flags")
			}

			require.NotPanics(t, parse, "should not parse nil base flags")
		}

		var nilBase *BaseFlags
		assertParseNils(t, nilBase)

		res := ""
		_, base := getSet(&res)
		base.flagSet = nil

		assertParseNils(t, nilBase)
		require.Empty(t, res, "should not parse nil base flags")
	})
}
