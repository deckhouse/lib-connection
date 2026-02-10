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

package config

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/deckhouse/lib-dhctl/pkg/log"
	"github.com/hashicorp/go-multierror"
	"github.com/name212/govalue"
	flag "github.com/spf13/pflag"

	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/utils"
	"github.com/deckhouse/lib-connection/pkg/ssh/utils/terminal"
	"github.com/deckhouse/lib-connection/pkg/utils/defaults"
	"github.com/deckhouse/lib-connection/pkg/utils/env"
	"github.com/deckhouse/lib-connection/pkg/utils/file"
	baseflags "github.com/deckhouse/lib-connection/pkg/utils/flags"
)

const (
	AgentPrivateKeysEnv          = "SSH_AGENT_PRIVATE_KEYS"
	BastionHostEnv               = "SSH_BASTION_HOST"
	BastionUserEnv               = "SSH_BASTION_USER"
	BastionPortEnv               = "SSH_BASTION_PORT"
	UserEnv                      = "SSH_USER"
	HostsEnv                     = "SSH_HOSTS"
	PortEnv                      = "SSH_PORT"
	ExtraArgsEnv                 = "SSH_EXTRA_ARGS"
	ConnectionConfigEnv          = "CONNECTION_CONFIG"
	LegacyModeEnv                = "SSH_LEGACY_MODE"
	ModernModeEnv                = "SSH_MODERN_MODE"
	AskBastionPasswordEnv        = "ASK_BASTION_PASS"
	AskSudoPasswordEnv           = "ASK_BECOME_PASS"
	ForceNoPrivateKeysEnv        = "FORCE_NO_PRIVATE_KEYS"
	UseAgentWithNoPrivateKeysEnv = "USE_AGENT_WITH_NO_PRIVATE_KEYS"
)

const (
	sshHostsFlag                  = "ssh-host"
	legacyModeFlag                = "ssh-legacy-mode"
	modernModeFlag                = "ssh-modern-mode"
	connectionConfigFlag          = "connection-config"
	askSudoPasswordFlag           = "ask-become-pass"
	privateKeysFlag               = "ssh-agent-private-keys"
	forceNoPrivateKeysFlag        = "force-no-private-keys"
	useAgentWithNoPrivateKeysFlag = "use-agent-with-no-private-keys"
)

type Flags struct {
	Mode

	PrivateKeysPaths []string

	BastionHost string
	BastionPort int
	BastionUser string

	User  string
	Hosts []string
	Port  int

	ExtraArgs string

	ConnectionConfigPath string

	AskBastionPass bool
	AskSudoPass    bool

	forceNoPrivateKeys        bool
	useAgentWithNoPrivateKeys bool

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
	userPassedArguments := len(f.PrivateKeysPaths) > 0 ||
		f.BastionHost != "" ||
		f.BastionUser != "" ||
		f.BastionPort != 0 ||
		len(f.Hosts) > 0 ||
		f.User != "" ||
		f.Port != 0 ||
		f.ExtraArgs != ""

	if userPassedArguments && f.ConnectionConfigPath != "" {
		return fmt.Errorf("Cannot use both --%s and --ssh-* flags or envs at the same time", connectionConfigFlag)
	}

	return nil
}

func (f *Flags) FillDefaults() error {
	if len(f.PrivateKeysPaths) == 0 && !f.forceNoPrivateKeys {
		home, err := defaults.HomeDir(f.baseFlags.EnvExtractor())
		if err != nil {
			return err
		}

		f.PrivateKeysPaths = []string{filepath.Join(home, ".ssh", "id_rsa")}
	}

	getUser := f.userExtractor()
	var err error

	if f.User == "" {
		f.User, err = getUser()
		if err != nil {
			return err
		}
	}

	if f.BastionUser == "" {
		f.BastionUser, err = getUser()
		if err != nil {
			return err
		}
	}

	if f.BastionPort == 0 {
		f.BastionPort = DefaultPort
	}

	if f.Port == 0 {
		f.Port = DefaultPort
	}

	// if not use private keys force ask sudo pass
	if f.forceNoPrivateKeys {
		if !f.AskSudoPass && !f.useAgentWithNoPrivateKeys {
			f.AskSudoPass = true
		}
	}

	return nil
}

func (f *Flags) RewriteFromEnvs() error {
	envExtractor, err := f.baseFlags.ShouldEnvExtractor()
	if err != nil {
		return err
	}

	privateKeysVal := env.NewVar(AgentPrivateKeysEnv, &f.PrivateKeysPaths)

	err = envExtractor.ExtractAllVars(
		env.NewVar(BastionPortEnv, &f.BastionPort),
		env.NewVar(PortEnv, &f.Port),
		env.NewVar(ForceNoPrivateKeysEnv, &f.forceNoPrivateKeys),
		env.NewVar(UseAgentWithNoPrivateKeysEnv, &f.useAgentWithNoPrivateKeys),
		privateKeysVal,
		env.NewVar(BastionHostEnv, &f.BastionHost),
		env.NewVar(BastionUserEnv, &f.BastionUser),
		env.NewVar(UserEnv, &f.User),
		env.NewVar(HostsEnv, &f.Hosts),
		env.NewVar(ExtraArgsEnv, &f.ExtraArgs),
		env.NewVar(ConnectionConfigEnv, &f.ConnectionConfigPath),
		env.NewVar(LegacyModeEnv, &f.ForceLegacy),
		env.NewVar(ModernModeEnv, &f.ForceModern),
		env.NewVar(AskBastionPasswordEnv, &f.AskBastionPass),
		env.NewVar(AskSudoPasswordEnv, &f.AskSudoPass),
	)

	if err != nil {
		return err
	}

	if !f.forceNoPrivateKeys {
		if privateKeysVal.Present && len(f.PrivateKeysPaths) == 0 {
			f.forceNoPrivateKeys = true
		}
	}

	return nil
}

// ExtractConfig
// if args is nil used os.Args
func (f *Flags) ExtractConfig(args []string, opts ...ValidateOption) (*ConnectionConfig, error) {
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

	return f.parser.ExtractConfigAfterParse(f, opts...)
}

func (f *Flags) userExtractor() func() (string, error) {
	var currentUser *string

	return func() (string, error) {
		if currentUser != nil {
			return *currentUser, nil
		}

		envExtractor, err := f.baseFlags.ShouldEnvExtractor()
		if err != nil {
			return "", err
		}

		userName, err := defaults.CurrentUserName(envExtractor)
		if err != nil {
			return "", err
		}

		currentUser = &userName

		return userName, nil
	}
}

type (
	AskPasswordFunc         func(promt string) ([]byte, error)
	PrivateKeyExtractorFunc func(path string, logger log.Logger) (password string, err error)
)

type FlagsParser struct {
	*baseflags.BaseParser

	ask AskPasswordFunc

	// extractPrivateKey
	// custom extract content and password for private key file
	// need to rewrite for testing purposes
	extractPrivateKey PrivateKeyExtractorFunc
}

// NewFlagsParser
// init FlagsParser
// prefix will trim right all _ ang - symbols and spaces left and right from settings.Settings EnvsPrefix
// By default parser add _ after prefix for all env vars
func NewFlagsParser(sett settings.Settings) *FlagsParser {
	askFromTerminal := func(prompt string) ([]byte, error) {
		return terminal.AskPassword(sett.Logger(), prompt)
	}

	terminalPrivateKeyPasswordExtractorWithoutDefault := func(path string, logger log.Logger) (string, error) {
		return terminalPrivateKeyPasswordExtractor(path, make([]byte, 0), logger)
	}

	parser := &FlagsParser{
		BaseParser: baseflags.NewBaseParser(sett),
	}

	return parser.WithAsk(askFromTerminal).
		WithPrivateKeyPasswordExtractor(terminalPrivateKeyPasswordExtractorWithoutDefault)
}

func (p *FlagsParser) WithAsk(ask AskPasswordFunc) *FlagsParser {
	if govalue.Nil(ask) {
		p.Settings().Logger().WarnF("Ask function is nil. Skip set ask function.")
		return p
	}

	p.ask = ask
	return p
}

func (p *FlagsParser) WithPrivateKeyPasswordExtractor(extractor PrivateKeyExtractorFunc) *FlagsParser {
	if govalue.Nil(extractor) {
		p.Settings().Logger().WarnF("Private key password extractor function is nil. Skip set extractor function.")
		return p
	}

	p.extractPrivateKey = extractor
	return p
}

// InitFlags
// init flag.FlagSet and return struct with flags where flag.FlagSet parsed
// should call before flag.Parse or flag.FlagSet.Parse
// if set is parsed returns error
func (p *FlagsParser) InitFlags(set *flag.FlagSet) (*Flags, error) {
	if set.Parsed() {
		return nil, fmt.Errorf("Flags already parsed")
	}

	internalSet := flag.NewFlagSet("lib-connection-ssh-internal", flag.ContinueOnError)

	envsExtractor := p.NewEnvsExtractor()

	flags := &Flags{
		baseFlags: baseflags.NewBaseFlags(internalSet, envsExtractor, baseflags.BaseFlagsSkipUnknownFlags()),
		parser:    p,
	}

	internalSet = flags.baseFlags.FlagSet()

	p.fillFlagsToSet(internalSet, flags, envsExtractor)

	// we need fake set for prevent writing flags multiple times
	// but we should provide helps to parent set
	fakeSet := flag.NewFlagSet("lib-connection-ssh", flag.ExitOnError)
	fakeFlags := &Flags{}

	p.fillFlagsToSet(fakeSet, fakeFlags, envsExtractor)

	set.AddFlagSet(fakeSet)

	return flags, nil
}

// ExtractConfigAfterParse
// extract ConnectionConfig from flags
// Flags contains copy of set. For parse use Flags.Parse
// if flag.FlagSet in Flags is not parse returns error
func (p *FlagsParser) ExtractConfigAfterParse(flags *Flags, opts ...ValidateOption) (*ConnectionConfig, error) {
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

	if flags.ConnectionConfigPath != "" {
		configReader, err := file.Reader(flags.ConnectionConfigPath, "connection config")
		if err != nil {
			return nil, err
		}

		defer func() {
			if err := configReader.Close(); err != nil {
				logger.DebugF("Error closing config file: %v", err)
			}
		}()

		return ParseConnectionConfig(configReader, sett, opts...)
	}

	if err := flags.FillDefaults(); err != nil {
		return nil, err
	}

	options := &validateOptions{}
	for _, o := range opts {
		o(options)
	}

	// TODO prepare connection configuration and use ParseConnectionConfig
	// for one place check
	// unfortunately we cannot handle error from ParseConnectionConfig
	// we should parse error string but it is hard in current time

	hosts := make([]Host, 0, len(flags.Hosts))
	for _, h := range flags.Hosts {
		hosts = append(hosts, Host{
			Host: h,
		})
	}

	if flags.forceNoPrivateKeys && flags.useAgentWithNoPrivateKeys {
		authSockPath := p.Settings().AuthSock()
		if err := file.IsExists(authSockPath, "auth socket from env "+settings.SSHAgentAuthSockEnv); err != nil {
			return nil, err
		}
	}

	err := validateOnlyUniqueHosts(hosts, options).flagsError()
	if err != nil {
		return nil, err
	}

	if flags.ForceLegacy && flags.ForceModern {
		return nil, fmt.Errorf("--%s and --%s cannot be use both", legacyModeFlag, modernModeFlag)
	}

	privateKeys, err := p.readPrivateKeysFromFlags(flags, logger)
	if err != nil {
		return nil, fmt.Errorf("Failed to read private keys from flags: %w", err)
	}

	passwords, err := p.getPasswordsFromUser(flags)

	if err != nil {
		return nil, err
	}

	res := &ConnectionConfig{
		Config: &Config{
			Mode: Mode{
				ForceLegacy: flags.ForceLegacy,
				ForceModern: flags.ForceModern,
			},

			User: flags.User,
			Port: intPtr(flags.Port),

			PrivateKeys: privateKeys,

			ExtraArgs: flags.ExtraArgs,

			BastionHost:     flags.BastionHost,
			BastionPort:     intPtr(flags.BastionPort),
			BastionUser:     flags.BastionUser,
			BastionPassword: passwords.Bastion,

			SudoPassword: passwords.Sudo,

			ForceUseSSHAgent: flags.useAgentWithNoPrivateKeys,
		},
		Hosts: hosts,
	}

	if !res.Config.HaveAuthMethods() {
		return nil, fmt.Errorf(
			"No auth methods configured. Please pass --%s and/or --%s or --%s with --%s or --%s with --%s",
			privateKeysFlag,
			askSudoPasswordFlag,
			forceNoPrivateKeysFlag,
			askSudoPasswordFlag,
			forceNoPrivateKeysFlag,
			useAgentWithNoPrivateKeysFlag,
		)
	}

	return res, nil
}

// ParseFlagsAndExtractConfig
// initialize, parse and extract ConnectionConfig from flags
// set flag.FlagSet can be nil. If nil, func initialize new flag.FlagSet
// if arguments is nil extract arguments from os.Args
func (p *FlagsParser) ParseFlagsAndExtractConfig(arguments []string, set *flag.FlagSet, opts ...ValidateOption) (*ConnectionConfig, error) {
	if govalue.Nil(set) {
		set = flag.NewFlagSet("ssh-connection", flag.ExitOnError)
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

	return p.ExtractConfigAfterParse(flags, opts...)
}

func (p *FlagsParser) fillFlagsToSet(set *flag.FlagSet, flags *Flags, envsExtractor *env.Extractor) {
	set.StringSliceVar(
		&flags.PrivateKeysPaths,
		privateKeysFlag,
		make([]string, 0),
		envsExtractor.AddEnvToUsage(
			"Paths to private keys. Those keys will be used to connect to servers and to the bastion. Can be specified multiple times (default: '~/.ssh/id_rsa').",
			AgentPrivateKeysEnv,
		),
	)

	set.StringVar(
		&flags.BastionHost,
		"ssh-bastion-host",
		"",
		envsExtractor.AddEnvToUsage(
			"Jumper (bastion) host to connect to servers (will be used both by infrastructure creation utility and ansible). Only IPs or hostnames are supported, name from ssh-config will not work.",
			BastionHostEnv,
		),
	)

	set.IntVar(
		&flags.BastionPort,
		"ssh-bastion-port",
		0,
		envsExtractor.AddEnvToUsage(
			"SSH bastion port.",
			BastionPortEnv,
		),
	)

	set.StringVar(
		&flags.BastionUser,
		"ssh-bastion-user",
		"",
		envsExtractor.AddEnvToUsage(
			"User to authenticate under when connecting to bastion (default: $USER).",
			BastionUserEnv,
		),
	)

	set.StringSliceVar(
		&flags.Hosts,
		sshHostsFlag,
		make([]string, 0),
		envsExtractor.AddEnvToUsage(
			"SSH destination hosts, can be specified multiple times.",
			HostsEnv,
		),
	)

	set.StringVar(
		&flags.User,
		"ssh-user",
		"",
		envsExtractor.AddEnvToUsage(
			"User to authenticate under (default: $USER).",
			UserEnv,
		),
	)

	set.IntVar(
		&flags.Port,
		"ssh-port",
		0,
		envsExtractor.AddEnvToUsage(
			"SSH destination port.",
			PortEnv,
		),
	)

	set.StringVar(
		&flags.ExtraArgs,
		"ssh-extra-args",
		"",
		envsExtractor.AddEnvToUsage(
			"Extra args for ssh commands (like -vvv).",
			ExtraArgsEnv,
		),
	)

	set.StringVar(
		&flags.ConnectionConfigPath,
		"connection-config",
		"",
		envsExtractor.AddEnvToUsage(
			"SSH connection config file path.",
			ConnectionConfigEnv,
		),
	)

	set.BoolVar(
		&flags.ForceLegacy,
		legacyModeFlag,
		false,
		envsExtractor.AddEnvToUsage(
			"Force legacy SSH mode.",
			LegacyModeEnv,
		),
	)

	set.BoolVar(
		&flags.ForceModern,
		modernModeFlag,
		false,
		envsExtractor.AddEnvToUsage(
			"Force modern SSH mode.",
			ModernModeEnv,
		),
	)

	set.BoolVar(
		&flags.AskBastionPass,
		"ask-bastion-pass",
		false,
		envsExtractor.AddEnvToUsage(
			"Ask for bastion password before the installation process.",
			AskBastionPasswordEnv,
		),
	)

	set.BoolVarP(
		&flags.AskSudoPass,
		askSudoPasswordFlag,
		"K",
		false,
		envsExtractor.AddEnvToUsage(
			"Ask for sudo password before the installation process.",
			AskSudoPasswordEnv,
		),
	)

	set.BoolVar(
		&flags.forceNoPrivateKeys,
		forceNoPrivateKeysFlag,
		false,
		envsExtractor.AddEnvToUsage(
			"Do not use private keys.",
			ForceNoPrivateKeysEnv,
		),
	)

	set.BoolVar(
		&flags.useAgentWithNoPrivateKeys,
		useAgentWithNoPrivateKeysFlag,
		false,
		envsExtractor.AddEnvToUsage(
			fmt.Sprintf(
				"Do not ask sudo password if private keys did not provided. Use with '--%s' Force use ssh agent over %s",
				forceNoPrivateKeysFlag,
				settings.SSHAgentAuthSockEnv,
			),
			UseAgentWithNoPrivateKeysEnv,
		),
	)
}

func (p *FlagsParser) readPrivateKeysFromFlags(flags *Flags, logger log.Logger) ([]AgentPrivateKey, error) {
	res := make([]AgentPrivateKey, 0, len(flags.PrivateKeysPaths))

	if len(flags.PrivateKeysPaths) == 0 {
		return res, nil
	}

	pathsParsed := make(map[string]struct{}, len(flags.PrivateKeysPaths))
	var parseErr *multierror.Error
	for _, path := range flags.PrivateKeysPaths {
		if _, ok := pathsParsed[path]; ok {
			logger.DebugF("Multiple private keys found for %s", path)
			continue
		}

		pathsParsed[path] = struct{}{}

		fullPath, err := file.FullPath(path, "private key")
		if err != nil {
			return nil, err
		}

		keysPassword, err := p.extractPrivateKey(fullPath, logger)
		if err != nil {
			parseErr = multierror.Append(parseErr, fmt.Errorf("cannot parse private key file %s: %w", path, err))
			continue
		}

		res = append(res, AgentPrivateKey{
			Key:        fullPath,
			Passphrase: keysPassword,
			IsPath:     true,
		})
	}

	if err := parseErr.ErrorOrNil(); err != nil {
		return nil, err
	}

	return res, nil
}

func (p *FlagsParser) getPasswordsFromUser(flags *Flags) (*passwordsFromUser, error) {
	res := &passwordsFromUser{}

	if flags.AskBastionPass {
		bastionPass, err := p.ask("[bastion] Password: ")
		if err != nil {
			return nil, fmt.Errorf("Cannot get bastion password: %w", err)
		}
		res.Bastion = string(bastionPass)
	}

	if flags.AskSudoPass {
		sudoPass, err := p.ask("[sudo] Password: ")
		if err != nil {
			return nil, fmt.Errorf("Cannot get sudo password: %w", err)
		}

		res.Sudo = string(sudoPass)
	}

	return res, nil
}

func terminalPrivateKeyPasswordExtractor(path string, defaultPassword []byte, logger log.Logger) (string, error) {
	_, password, err := utils.ParseSSHPrivateKeyFile(path, string(defaultPassword), logger)

	return password, err
}

type passwordsFromUser struct {
	Sudo    string
	Bastion string
}

func intPtr(i int) *int {
	if i == 0 {
		return nil
	}
	return &i
}

func (h notUniqueHosts) flagsError() error {
	errs := make([]string, 0)

	if h.noHosts {
		errs = append(errs, fmt.Sprintf("SSH hosts for connection is required. Please pass hosts for connection via --%s flag", sshHostsFlag))
	}

	for host, count := range h.hosts {
		errs = append(errs, notUniqueHostErr(host, count))
	}

	if len(errs) == 0 {
		return nil
	}

	sort.Strings(errs)

	errsJoined := "\t" + strings.Join(errs, "\n\t")
	return fmt.Errorf("--%s flag parse errors:\n%s", sshHostsFlag, errsJoined)
}
