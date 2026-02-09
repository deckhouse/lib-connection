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
	"fmt"
	"os"

	"github.com/name212/govalue"
	flag "github.com/spf13/pflag"

	"github.com/deckhouse/lib-connection/pkg/utils/env"
)

type BaseFlagsOpts struct {
	skipUnknownFlags bool
}

type BaseFlagsOpt func(f *BaseFlagsOpts)

func BaseFlagsSkipUnknownFlags() BaseFlagsOpt {
	return func(f *BaseFlagsOpts) {
		f.skipUnknownFlags = true
	}
}

type BaseFlags struct {
	flagSet      *flag.FlagSet
	envExtractor *env.Extractor
}

// NewBaseFlags
// contains copy of flagsSet
func NewBaseFlags(flagSet *flag.FlagSet, envExtractor *env.Extractor, opts ...BaseFlagsOpt) *BaseFlags {
	options := &BaseFlagsOpts{}
	for _, o := range opts {
		o(options)
	}

	set := *flagSet
	if options.skipUnknownFlags {
		set.ParseErrorsAllowlist.UnknownFlags = true
	}

	return &BaseFlags{
		flagSet:      &set,
		envExtractor: envExtractor,
	}
}

func (f *BaseFlags) Parse(args []string) error {
	if f == nil || f.flagSet == nil {
		return fmt.Errorf("flags is not initialized. flagSet is nil")
	}

	if args == nil {
		args = os.Args[1:]
	}

	return f.flagSet.Parse(args)
}

func (f *BaseFlags) IsValid() error {
	if govalue.Nil(f) {
		return notInitializedError("baseFlags")
	}

	if govalue.Nil(f.envExtractor) {
		return notInitializedEnvExtractorError()
	}

	if govalue.Nil(f.flagSet) {
		return notInitializedError("flagSet")
	}

	return nil
}

func (f *BaseFlags) IsInitialized() error {
	if err := f.IsValid(); err != nil {
		return err
	}

	if !f.flagSet.Parsed() {
		return fmt.Errorf("flagsSet is not parsed. Call flag.Parse or flag.FlagSet.Parse before extract config")
	}

	return nil
}

func (f *BaseFlags) EnvExtractor() *env.Extractor {
	return f.envExtractor
}

func (f *BaseFlags) ShouldEnvExtractor() (*env.Extractor, error) {
	if govalue.Nil(f.envExtractor) {
		return nil, notInitializedEnvExtractorError()
	}

	return f.envExtractor, nil
}

func (f *BaseFlags) FlagSet() *flag.FlagSet {
	return f.flagSet
}

func notInitializedEnvExtractorError() error {
	return notInitializedError("envExtractor")
}

func notInitializedError(field string) error {
	return fmt.Errorf(
		"Internal error. %s in Flags did not initialize. Call InitFlags first and pass Flags from result of InitFlags",
		field,
	)
}
