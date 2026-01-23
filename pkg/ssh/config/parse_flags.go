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
	"io"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/deckhouse/lib-dhctl/pkg/log"
	"github.com/hashicorp/go-multierror"
	"github.com/name212/govalue"
	flag "github.com/spf13/pflag"

	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/utils"
	"github.com/deckhouse/lib-connection/pkg/ssh/utils/terminal"
)

const (
	AgentPrivateKeysEnv   = "SSH_AGENT_PRIVATE_KEYS"
	BastionHostEnv        = "SSH_BASTION_HOST"
	BastionUserEnv        = "SSH_BASTION_USER"
	BastionPortEnv        = "SSH_BASTION_PORT"
	UserEnv               = "SSH_USER"
	HostsEnv              = "SSH_HOSTS"
	PortEnv               = "SSH_PORT"
	ExtraArgsEnv          = "SSH_EXTRA_ARGS"
	ConnectionConfigEnv   = "CONNECTION_CONFIG"
	LegacyModeEnv         = "SSH_LEGACY_MODE"
	ModernModeEnv         = "SSH_MODERN_MODE"
	AskBastionPasswordEnv = "ASK_BASTION_PASS"
	AskSudoPasswordEnv    = "ASK_BECOME_PASS"
)

const (
	sshHostsFlag         = "ssh-host"
	legacyModeFlag       = "ssh-legacy-mode"
	modernModeFlag       = "ssh-modern-mode"
	connectionConfigFlag = "connection-config"
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

	flagSet      *flag.FlagSet
	envExtractor *envExtractor
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
	if len(f.PrivateKeysPaths) == 0 {
		home, err := getHomeDir(f.envExtractor)
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
		f.BastionPort = 22
	}

	if f.Port == 0 {
		f.Port = 22
	}

	return nil
}

func (f *Flags) RewriteFromEnvs() error {
	if govalue.Nil(f.envExtractor) {
		return notInitializedError("envExtractor")
	}

	f.envExtractor.Strings(AgentPrivateKeysEnv, &f.PrivateKeysPaths)

	f.envExtractor.String(BastionHostEnv, &f.BastionHost)
	f.envExtractor.String(BastionUserEnv, &f.BastionUser)
	if err := f.envExtractor.Int(BastionPortEnv, &f.BastionPort); err != nil {
		return err
	}

	f.envExtractor.String(UserEnv, &f.User)
	f.envExtractor.Strings(HostsEnv, &f.Hosts)
	if err := f.envExtractor.Int(PortEnv, &f.Port); err != nil {
		return err
	}

	f.envExtractor.String(ExtraArgsEnv, &f.ExtraArgs)

	f.envExtractor.String(ConnectionConfigEnv, &f.ConnectionConfigPath)

	f.envExtractor.Bool(LegacyModeEnv, &f.ForceLegacy)
	f.envExtractor.Bool(ModernModeEnv, &f.ForceModernMode)

	f.envExtractor.Bool(AskBastionPasswordEnv, &f.AskBastionPass)
	f.envExtractor.Bool(AskSudoPasswordEnv, &f.AskSudoPass)

	return nil
}

func notInitializedError(field string) error {
	return fmt.Errorf(
		"Internal error. %s in Flags did not initialize. Call InitFlags first and pass Flags from result of InitFlags",
		field,
	)
}

func (f *Flags) IsInitialized() error {
	if govalue.Nil(f.envExtractor) {
		return notInitializedError("envExtractor")
	}

	if govalue.Nil(f.flagSet) {
		return notInitializedError("flagSet")
	}

	if !f.flagSet.Parsed() {
		return fmt.Errorf("flagsSet is not parsed. Call flag.Parse or flag.FlagSet.Parse before extract config")
	}

	return nil
}

func (f *Flags) userExtractor() func() (string, error) {
	var currentUser *string

	return func() (string, error) {
		if currentUser != nil {
			return *currentUser, nil
		}

		userName, err := getCurrentUser(f.envExtractor)
		if err != nil {
			return "", err
		}

		currentUser = &userName

		return userName, nil
	}
}

type (
	AskPasswordFunc         func(promt string) ([]byte, error)
	EnvsLookupFunc          func(name string) (string, bool)
	PrivateKeyExtractorFunc func(path string, logger log.Logger) (content string, password string, err error)
)

type FlagsParser struct {
	envsPrefix string
	ask        AskPasswordFunc
	sett       settings.Settings
	envsLookup EnvsLookupFunc

	// extractPrivateKey
	// custom extract content and password for private key file
	// need to rewrite for testing purposes
	extractPrivateKey PrivateKeyExtractorFunc
}

// NewFlagsParser
// init FlagsParser with empty envsPrefix
// trim right all _ ang - symbols and spaces left and right from sett.EnvsPrefix
// By default parser add _ after prefix for all env vars
func NewFlagsParser(sett settings.Settings) *FlagsParser {
	askFromTerminal := func(prompt string) ([]byte, error) {
		return terminal.AskPassword(sett.Logger(), prompt)
	}

	parser := &FlagsParser{
		sett: sett,
	}

	terminalPrivateKeyPasswordExtractorWithoutDefault := func(path string, logger log.Logger) (string, string, error) {
		return terminalPrivateKeyPasswordExtractor(path, make([]byte, 0), logger)
	}

	return parser.WithEnvsPrefix(sett.EnvsPrefix()).
		WithAsk(askFromTerminal).
		WithEnvsLookup(os.LookupEnv).
		WithPrivateKeyPasswordExtractor(terminalPrivateKeyPasswordExtractorWithoutDefault)
}

// WithEnvsPrefix
// This method trim right all _ ang - symbols and spaces left and right
// By default parser add _ after prefix for all env vars
func (p *FlagsParser) WithEnvsPrefix(envsPrefix string) *FlagsParser {
	envsPrefix = strings.TrimSpace(envsPrefix)
	envsPrefix = strings.TrimRight(envsPrefix, "_-")
	p.envsPrefix = envsPrefix
	return p
}

func (p *FlagsParser) WithAsk(ask AskPasswordFunc) *FlagsParser {
	if govalue.Nil(ask) {
		p.sett.Logger().WarnF("Ask function is nil. Skip set ask function.")
		return p
	}

	p.ask = ask
	return p
}

func (p *FlagsParser) WithEnvsLookup(lookup EnvsLookupFunc) *FlagsParser {
	if govalue.Nil(lookup) {
		p.sett.Logger().WarnF("Envs lookup function is nil. Skip set ask function.")
		return p
	}

	p.envsLookup = lookup
	return p
}

func (p *FlagsParser) WithPrivateKeyPasswordExtractor(extractor PrivateKeyExtractorFunc) *FlagsParser {
	if govalue.Nil(extractor) {
		p.sett.Logger().WarnF("Private key password extractor function is nil. Skip set extractor function.")
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

	extractorFromEnv := p.envsExtractor()

	flags := &Flags{
		flagSet:      set,
		envExtractor: extractorFromEnv,
	}

	set.StringSliceVar(
		&flags.PrivateKeysPaths,
		"ssh-agent-private-keys",
		make([]string, 0),
		extractorFromEnv.AddEnvToUsage(
			"Paths to private keys. Those keys will be used to connect to servers and to the bastion. Can be specified multiple times (default: '~/.ssh/id_rsa').",
			AgentPrivateKeysEnv,
		),
	)

	set.StringVar(
		&flags.BastionHost,
		"ssh-bastion-host",
		"",
		extractorFromEnv.AddEnvToUsage(
			"Jumper (bastion) host to connect to servers (will be used both by infrastructure creation utility and ansible). Only IPs or hostnames are supported, name from ssh-config will not work.",
			BastionHostEnv,
		),
	)

	set.IntVar(
		&flags.BastionPort,
		"ssh-bastion-port",
		0,
		extractorFromEnv.AddEnvToUsage(
			"SSH bastion port.",
			BastionPortEnv,
		),
	)

	set.StringVar(
		&flags.BastionUser,
		"ssh-bastion-user",
		"",
		extractorFromEnv.AddEnvToUsage(
			"User to authenticate under when connecting to bastion (default: $USER).",
			BastionUserEnv,
		),
	)

	set.StringSliceVar(
		&flags.Hosts,
		sshHostsFlag,
		make([]string, 0),
		extractorFromEnv.AddEnvToUsage(
			"SSH destination hosts, can be specified multiple times.",
			HostsEnv,
		),
	)

	set.StringVar(
		&flags.User,
		"ssh-user",
		"",
		extractorFromEnv.AddEnvToUsage(
			"User to authenticate under (default: $USER).",
			UserEnv,
		),
	)

	set.IntVar(
		&flags.Port,
		"ssh-port",
		0,
		extractorFromEnv.AddEnvToUsage(
			"SSH destination port.",
			PortEnv,
		),
	)

	set.StringVar(
		&flags.ExtraArgs,
		"ssh-extra-args",
		"",
		extractorFromEnv.AddEnvToUsage(
			"Extra args for ssh commands (like -vvv).",
			ExtraArgsEnv,
		),
	)

	set.StringVar(
		&flags.ConnectionConfigPath,
		"connection-config",
		"",
		extractorFromEnv.AddEnvToUsage(
			"SSH connection config file path.",
			ConnectionConfigEnv,
		),
	)

	set.BoolVar(
		&flags.ForceLegacy,
		legacyModeFlag,
		false,
		extractorFromEnv.AddEnvToUsage(
			"Force legacy SSH mode.",
			LegacyModeEnv,
		),
	)

	set.BoolVar(
		&flags.ForceModernMode,
		modernModeFlag,
		false,
		extractorFromEnv.AddEnvToUsage(
			"Force modern SSH mode.",
			ModernModeEnv,
		),
	)

	set.BoolVar(
		&flags.AskBastionPass,
		"ask-bastion-pass",
		false,
		extractorFromEnv.AddEnvToUsage(
			"Ask for bastion password before the installation process.",
			AskBastionPasswordEnv,
		),
	)

	set.BoolVarP(
		&flags.AskSudoPass,
		"ask-become-pass",
		"K",
		false,
		extractorFromEnv.AddEnvToUsage(
			"Ask for sudo password before the installation process.",
			AskSudoPasswordEnv,
		),
	)

	return flags, nil
}

// ExtractConfigAfterParse
// extract ConnectionConfig from flags
// should call after InitFlags and flag.Parse or flag.FlagSet.Parse
// if flag.FlagSet in Flags is not parse returns error
func (p *FlagsParser) ExtractConfigAfterParse(flags *Flags, opts ...ValidateOption) (*ConnectionConfig, error) {
	if err := flags.IsInitialized(); err != nil {
		return nil, err
	}

	if err := flags.RewriteFromEnvs(); err != nil {
		return nil, err
	}

	if err := flags.IsConflictBetweenFlags(); err != nil {
		return nil, err
	}

	logger := p.sett.Logger()

	if flags.ConnectionConfigPath != "" {
		configReader, err := fileReader(flags.ConnectionConfigPath, "connection config")
		if err != nil {
			return nil, err
		}

		defer func() {
			if err := configReader.Close(); err != nil {
				logger.DebugF("Error closing config file: %v", err)
			}
		}()

		return ParseConnectionConfig(configReader, p.sett, opts...)
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

	err := validateOnlyUniqueHosts(hosts, options).flagsError()
	if err != nil {
		return nil, err
	}

	if flags.ForceLegacy && flags.ForceModernMode {
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

	return &ConnectionConfig{
		Config: &Config{
			Mode: Mode{
				ForceLegacy:     flags.ForceLegacy,
				ForceModernMode: flags.ForceModernMode,
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
		},
		Hosts: hosts,
	}, nil
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

	if arguments == nil {
		arguments = os.Args[1:]
	}

	if err := set.Parse(arguments); err != nil {
		return nil, err
	}

	return p.ExtractConfigAfterParse(flags, opts...)
}

func (p *FlagsParser) envsExtractor() *envExtractor {
	return newEnvExtractor(p.envsPrefix, p.envsLookup)
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

		content, keysPassword, err := p.extractPrivateKey(path, logger)
		if err != nil {
			parseErr = multierror.Append(parseErr, fmt.Errorf("cannot parse private key file %s: %w", path, err))
			continue
		}

		res = append(res, AgentPrivateKey{
			Key:        content,
			Passphrase: keysPassword,
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

func getHomeDir(extractor *envExtractor) (string, error) {
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

// getCurrentUser
// returns current user name
// first attempt get user from env
// can be call multiple times because user.Current() cache user info
func getCurrentUser(extractor *envExtractor) (string, error) {
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

func fileReader(path string, fileType string) (io.ReadCloser, error) {
	fullPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("Cannot get abs path for %s: %w", path, err)
	}

	stat, err := os.Stat(fullPath)
	if err != nil {
		return nil, fmt.Errorf("Cannot get %s file info for %s: %w", fileType, fullPath, err)
	}

	if stat.IsDir() || !stat.Mode().IsRegular() {
		return nil, fmt.Errorf("%s path '%s' should be regular file", fileType, fullPath)
	}

	return os.Open(fullPath)
}

type envExtractor struct {
	prefix     string
	lookupFunc func(string) (string, bool)
}

func newEnvExtractor(prefix string, lookupFunc EnvsLookupFunc) *envExtractor {
	return &envExtractor{
		prefix:     prefix,
		lookupFunc: lookupFunc,
	}
}

func (e *envExtractor) NameWithPrefix(name string) string {
	if e.prefix != "" {
		name = fmt.Sprintf("%s_%s", e.prefix, name)
	}

	return name
}

func (e *envExtractor) AddEnvToUsage(usage string, envName string) string {
	if envName == "" {
		return usage
	}

	return fmt.Sprintf("%s (Can rewrite with %s env)", usage, e.NameWithPrefix(envName))
}

func (e *envExtractor) Var(name string) (string, bool) {
	return e.lookupFunc(e.NameWithPrefix(name))
}

func (e *envExtractor) VarWithoutPrefix(name string) (string, bool) {
	return e.lookupFunc(name)
}

func (e *envExtractor) Int(name string, destination *int) error {
	strVar, ok := e.Var(name)
	if !ok {
		return nil
	}

	value, err := strconv.Atoi(strVar)
	if err != nil {
		return fmt.Errorf("Cannot convert '%s' to int for %s: %w", strVar, e.NameWithPrefix(name), err)
	}

	*destination = value

	return nil
}

func (e *envExtractor) StringWithoutPrefix(name string, destination *string) {
	strVar, ok := e.VarWithoutPrefix(name)
	if !ok {
		return
	}

	*destination = strVar
}

func (e *envExtractor) String(name string, destination *string) {
	strVar, ok := e.Var(name)
	if !ok {
		return
	}

	*destination = strVar
}

func (e *envExtractor) Strings(name string, destination *[]string) {
	valsStr, ok := e.Var(name)
	if !ok {
		return
	}

	valsSplit := strings.Split(valsStr, ",")
	vals := make([]string, 0, len(valsSplit))
	for _, v := range valsSplit {
		if strings.TrimSpace(v) != "" {
			vals = append(vals, v)
		}
	}

	*destination = vals
}

func (e *envExtractor) Bool(name string, destination *bool) {
	strVar, ok := e.Var(name)
	if !ok {
		return
	}
	value := strVar != ""

	*destination = value
}

func terminalPrivateKeyPasswordExtractor(path string, defaultPassword []byte, logger log.Logger) (string, string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("Cannot read private key %s: %w", path, err)
	}

	_, password, err := utils.ParseSSHPrivateKey(
		content,
		path,
		utils.NewTerminalPassphraseConsumer(logger, defaultPassword),
	)

	return string(content), password, err
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
	var errs []string
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
