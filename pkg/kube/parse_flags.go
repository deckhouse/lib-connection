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
	"fmt"

	"github.com/deckhouse/lib-dhctl/pkg/log"
	"github.com/name212/govalue"
	flag "github.com/spf13/pflag"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/utils/env"
	"github.com/deckhouse/lib-connection/pkg/utils/file"
	baseflags "github.com/deckhouse/lib-connection/pkg/utils/flags"
)

const (
	ConfigEnv            = "KUBE_CONFIG"
	ConfigContextEnv     = "KUBE_CONFIG_CONTEXT"
	ClientFromClusterEnv = "KUBE_CLIENT_FROM_CLUSTER"
)

const (
	kubeConfigFlag        = "kubeconfig"
	kubeConfigContextFlag = "kubeconfig-context"
	clientFromClusterFlag = "kube-client-from-cluster"
)

type Flags struct {
	Config

	baseFlags *baseflags.BaseFlags
	parser    *FlagsParser
}

// Parse
// pass nil if we should use os.Args
func (f *Flags) Parse(args []string) error {
	// Parse check that flags is initialized
	return f.baseFlags.Parse(args)
}

func (f *Flags) IsConflictBetweenFlags() error {
	if f.KubeConfig != "" && f.KubeConfigInCluster {
		envsExtractor, err := f.baseFlags.ShouldEnvExtractor()
		if err != nil {
			return err
		}

		return fmt.Errorf(
			"Cannot use both --%s and --%s or envs %s and %s at the same time",
			kubeConfigFlag,
			clientFromClusterFlag,
			envsExtractor.NameWithPrefix(ConfigEnv),
			envsExtractor.NameWithPrefix(ClientFromClusterEnv),
		)
	}

	return nil
}

func (f *Flags) RewriteFromEnvs() error {
	envExtractor, err := f.baseFlags.ShouldEnvExtractor()
	if err != nil {
		return err
	}

	err = envExtractor.ExtractAllVars(
		env.NewVar(ConfigEnv, &f.KubeConfig),
		env.NewVar(ConfigContextEnv, &f.KubeConfigContext),
		env.NewVar(ClientFromClusterEnv, &f.KubeConfigInCluster),
	)

	if err != nil {
		return err
	}

	if f.KubeConfig != "" || f.KubeConfigInCluster {
		return nil
	}

	envExtractor.StringWithoutPrefix("KUBECONFIG", &f.KubeConfig)

	return nil
}

// ExtractConfig
// if args not passed uses os.Args
func (f *Flags) ExtractConfig(args ...string) (*Config, error) {
	if err := f.baseFlags.IsValid(); err != nil {
		return nil, err
	}

	if govalue.Nil(f.parser) {
		return nil, fmt.Errorf("flag parser cannot be set")
	}

	var cmdArgs []string
	if len(args) > 0 {
		cmdArgs = args
	}

	if err := f.baseFlags.Parse(cmdArgs); err != nil {
		return nil, err
	}

	return f.parser.ExtractConfigAfterParse(f)
}

type FlagsParser struct {
	*baseflags.BaseParser
}

// NewFlagsParser
// init FlagsParser
// prefix will trim right all _ ang - symbols and spaces left and right from settings.Settings EnvsPrefix
// By default parser add _ after prefix for all env vars
func NewFlagsParser(sett settings.Settings) *FlagsParser {
	return &FlagsParser{
		BaseParser: baseflags.NewBaseParser(sett),
	}
}

// InitFlags
// init flag.FlagSet and return struct with flags where flag.FlagSet parsed
// Flags contains copy of set. For parse use Flags.Parse
// if set is parsed returns error
func (p *FlagsParser) InitFlags(set *flag.FlagSet) (*Flags, error) {
	if set.Parsed() {
		return nil, fmt.Errorf("Flags already parsed")
	}

	internalSet := flag.NewFlagSet("lib-connection-kube-internal", flag.ContinueOnError)

	envsExtractor := p.NewEnvsExtractor()

	flags := &Flags{
		baseFlags: baseflags.NewBaseFlags(internalSet, envsExtractor, baseflags.BaseFlagsSkipUnknownFlags()),
		parser:    p,
	}

	internalSet = flags.baseFlags.FlagSet()

	p.fillFlagsToSet(internalSet, flags, envsExtractor)

	// we need fake set for prevent writing flags multiple times
	// but we should provide helps to parent set
	fakeSet := flag.NewFlagSet("lib-connection-kube", flag.ExitOnError)
	fakeFlags := &Flags{}

	p.fillFlagsToSet(fakeSet, fakeFlags, envsExtractor)

	set.AddFlagSet(fakeSet)

	return flags, nil
}

// ExtractConfigAfterParse
// extract ConnectionConfig from flags
// should call after InitFlags and flag.Parse or flag.FlagSet.Parse
// if flag.FlagSet in Flags is not parse returns error
func (p *FlagsParser) ExtractConfigAfterParse(flags *Flags) (*Config, error) {
	if err := flags.baseFlags.IsInitialized(); err != nil {
		return nil, err
	}

	if err := flags.RewriteFromEnvs(); err != nil {
		return nil, err
	}

	if err := flags.IsConflictBetweenFlags(); err != nil {
		return nil, err
	}

	sett := p.Settings()
	logger := sett.Logger()

	if err := p.validateKubeConfigWithContext(flags, logger); err != nil {
		return nil, err
	}

	return &Config{
		KubeConfig:          flags.KubeConfig,
		KubeConfigContext:   flags.KubeConfigContext,
		KubeConfigInCluster: flags.KubeConfigInCluster,
	}, nil
}

// ParseFlagsAndExtractConfig
// initialize, parse and extract ConnectionConfig from flags
// set flag.FlagSet can be nil. If nil, func initialize new flag.FlagSet
// if arguments is nil extract arguments from os.Args
func (p *FlagsParser) ParseFlagsAndExtractConfig(arguments []string, set *flag.FlagSet) (*Config, error) {
	if govalue.Nil(set) {
		set = flag.NewFlagSet("kube", flag.ExitOnError)
	}

	flags, err := p.InitFlags(set)
	if err != nil {
		return nil, err
	}

	internalSet := flags.baseFlags.FlagSet()
	internalSet.AddFlagSet(set)

	// nil arguments will rewrite from os.Args
	if err := flags.Parse(arguments); err != nil {
		return nil, err
	}

	return p.ExtractConfigAfterParse(flags)
}

func (p *FlagsParser) fillFlagsToSet(set *flag.FlagSet, flags *Flags, envsExtractor *env.Extractor) {
	set.StringVar(
		&flags.KubeConfig,
		kubeConfigFlag,
		"",
		envsExtractor.AddEnvToUsage(
			"Path to kubernetes config file.",
			ConfigContextEnv,
		),
	)

	set.StringVar(
		&flags.KubeConfigContext,
		kubeConfigContextFlag,
		"",
		envsExtractor.AddEnvToUsage(
			"Context from kubernetes config to connect to Kubernetes API.",
			ConfigContextEnv,
		),
	)

	set.BoolVar(
		&flags.KubeConfigInCluster,
		clientFromClusterFlag,
		false,
		envsExtractor.AddEnvToUsage(
			"Use in-cluster Kubernetes API access.",
			ClientFromClusterEnv,
		),
	)
}

func (p *FlagsParser) validateKubeConfigWithContext(flags *Flags, logger log.Logger) error {
	kubeConfigFile := flags.KubeConfig
	context := flags.KubeConfigContext

	if kubeConfigFile == "" {
		if context != "" {
			return fmt.Errorf("Pass context flag --%s without kubeconfig path --%s ", kubeConfigContextFlag, kubeConfigFlag)
		}

		return nil
	}

	content, fullPath, err := file.ReadFile(kubeConfigFile, "kube config", logger)
	if err != nil {
		return err
	}

	cfg, err := clientcmd.Load(content)
	if err != nil {
		return fmt.Errorf("Cannot parse kube config file '%s': %w", kubeConfigFile, err)
	}

	if context != "" {
		_, ok := cfg.Contexts[context]
		if !ok {
			return fmt.Errorf("Cannot find context '%s' in kube config %s", context, kubeConfigFile)
		}
	}

	flags.KubeConfig = fullPath

	return nil
}
