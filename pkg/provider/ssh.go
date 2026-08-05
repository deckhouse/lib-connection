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

package provider

import (
	"context"
	"errors"
	"fmt"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/name212/govalue"
	"golang.org/x/sync/singleflight"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/clissh"
	sshconfig "github.com/deckhouse/lib-connection/pkg/ssh/config"
	"github.com/deckhouse/lib-connection/pkg/ssh/gossh"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
	"github.com/deckhouse/lib-connection/pkg/utils/file"
)

var (
	_ connection.SSHProvider = &DefaultSSHProvider{}
	_ connection.SSHProvider = &ErrorSSHProvider{}

	_ connection.StandaloneClientProvider = &DefaultSSHProvider{}
	_ connection.StandaloneClientProvider = &ErrorSSHProvider{}
)

// ErrProviderCleanedUp is returned when Cleanup ran while a keyed client was
// being created. A caller which keeps using the provider after Cleanup can call
// again, the new call starts a new creation. A caller which is shutting down
// should stop retrying.
var ErrProviderCleanedUp = errors.New("ssh provider cleaned up")

type SSHClientOptions struct {
	InitializeNewAgent bool
	ForceGoSSH         bool
	LoopsParams        gossh.ClientLoopsParams
	StartClient        bool
	ClientID           string
}

type SSHClientOption func(options *SSHClientOptions)

func SSHClientWithNoInitializeAgent() SSHClientOption {
	return func(options *SSHClientOptions) {
		options.InitializeNewAgent = false
	}
}

func SSHClientWithForceGoSSH() SSHClientOption {
	return func(options *SSHClientOptions) {
		options.ForceGoSSH = true
	}
}
func SSHClientWithStartAfterCreate(f bool) SSHClientOption {
	return func(options *SSHClientOptions) {
		options.StartClient = f
	}
}

func SSHClientWithLoopsParams(params gossh.ClientLoopsParams) SSHClientOption {
	return func(options *SSHClientOptions) {
		options.LoopsParams = params
	}
}

func SSHClientWithID(id string) SSHClientOption {
	return func(options *SSHClientOptions) {
		options.ClientID = id
	}
}

type DefaultSSHProvider struct {
	mu sync.Mutex

	sett          settings.Settings
	options       SSHClientOptions
	goSSHStopWait time.Duration

	defaultConfig *sshconfig.ConnectionConfig
	currentClient connection.SSHClient

	additionalClients []connection.SSHClient

	keyedClients map[string]connection.SSHClient
	keyedFlights singleflight.Group
	// creations in flight, kept while they run to let a stop of the key abort them
	keyedCreations map[string]*keyedCreation

	// keyed clients keep this context for their internal reconnects, so it is
	// bound to the provider lifetime and not to the context of a single caller.
	// Cleanup cancels it to unblock reconnects of the clients it stops
	keyedClientsCtx    context.Context
	keyedClientsCancel context.CancelFunc

	privateKeysTmp              string
	writtenPrivateKeys          []session.AgentPrivateKey
	defaultPrivateKeysWithPaths []session.AgentPrivateKey
	privateKeysPrepared         bool
}

func NewDefaultSSHProvider(sett settings.Settings, config *sshconfig.ConnectionConfig, opts ...SSHClientOption) *DefaultSSHProvider {
	clonedConfig := config.Config.Clone().FillDefaults()
	clonedConnectionConfig := &sshconfig.ConnectionConfig{
		Hosts:  config.Hosts,
		Config: clonedConfig,
	}

	keyedClientsCtx, keyedClientsCancel := context.WithCancel(context.Background())

	provider := &DefaultSSHProvider{
		defaultConfig:      clonedConnectionConfig,
		sett:               sett,
		writtenPrivateKeys: make([]session.AgentPrivateKey, 0, 2),
		goSSHStopWait:      10 * time.Second,
		keyedClients:       make(map[string]connection.SSHClient),
		keyedCreations:     make(map[string]*keyedCreation),
		keyedClientsCtx:    keyedClientsCtx,
		keyedClientsCancel: keyedClientsCancel,
	}

	return provider.WithOptions(opts...)
}

func NewDefaultSSHProviderFromFlags(ctx context.Context, sett settings.Settings, flags *sshconfig.Flags, opts ...sshconfig.ValidateOption) (*DefaultSSHProvider, error) {
	parser := sshconfig.NewFlagsParser(ctx, sett)
	config, err := parser.ExtractConfigAfterParse(flags, opts...)
	if err != nil {
		return nil, err
	}

	return NewDefaultSSHProvider(sett, config), nil
}

func (p *DefaultSSHProvider) Client(ctx context.Context) (connection.SSHClient, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.doGetCurrentClient(ctx)
}

func (p *DefaultSSHProvider) NewAdditionalClient(ctx context.Context) (connection.SSHClient, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var sess *session.Session
	var privateKeys []session.AgentPrivateKey

	if !govalue.Nil(p.currentClient) {
		sess = p.currentClient.Session()
		privateKeys = p.currentClient.PrivateKeys()
	}

	client, err := p.createClient(ctx, sess, privateKeys)
	if err != nil {
		return nil, err
	}

	p.additionalClients = append(p.additionalClients, client)
	return client, nil
}

func (p *DefaultSSHProvider) NewStandaloneClient(ctx context.Context, sess *session.Session, privateKeys []session.AgentPrivateKey, opts ...connection.StandaloneClientOpt) (connection.SSHClient, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	client, err := p.createClient(ctx, sess, privateKeys, withStandaloneClientOpts(opts...))
	if err != nil {
		return nil, err
	}

	p.additionalClients = append(p.additionalClients, client)

	activeClients := 0
	for _, additionalClient := range p.additionalClients {
		if !govalue.Nil(additionalClient) && !additionalClient.IsStopped() {
			activeClients++
		}
	}

	fmt.Printf(
		"NewStandaloneClient: total=%d active=%d\n",
		len(p.additionalClients),
		activeClients,
	)

	p.debug(
		"NewStandaloneClient: additionalClients=%d activeClients=%d",
		len(p.additionalClients),
		activeClients,
	)

	return client, nil
}

func (p *DefaultSSHProvider) StandaloneClientFor(ctx context.Context, key string, sess *session.Session, privateKeys []session.AgentPrivateKey, opts ...connection.StandaloneClientOpt) (connection.SSHClient, error) {
	if sess == nil {
		return nil, fmt.Errorf("session is required for standalone client for key %s", key)
	}

	p.mu.Lock()
	cached := p.keyedClients[key]
	p.mu.Unlock()

	if !govalue.Nil(cached) && cached.Live() {
		return cached, nil
	}

	resCh := p.keyedFlights.DoChan(key, func() (any, error) {
		return p.createKeyedClient(key, sess, privateKeys, opts...)
	})

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("wait standalone client for key %s: %w", key, ctx.Err())
	case res := <-resCh:
		if res.Err != nil {
			return nil, res.Err
		}

		client, ok := res.Val.(connection.SSHClient)
		if !ok {
			panic(fmt.Sprintf("Possible bug in ssh provider: got %T instead of client for key %s", res.Val, key))
		}

		return client, nil
	}
}

func (p *DefaultSSHProvider) createKeyedClient(key string, sess *session.Session, privateKeys []session.AgentPrivateKey, opts ...connection.StandaloneClientOpt) (connection.SSHClient, error) {
	// recheck the cache: another flight may have stored a live client
	// after the fast path in StandaloneClientFor missed
	p.mu.Lock()
	cached := p.keyedClients[key]
	if !govalue.Nil(cached) {
		if cached.Live() {
			p.mu.Unlock()
			return cached, nil
		}

		delete(p.keyedClients, key)
	}
	p.mu.Unlock()

	// stop outside the provider lock, stopping a reconnecting client can block
	if !govalue.Nil(cached) {
		p.debug("Stopping dead client for key %s", key)
		cached.Stop()
	}

	// the client keeps the provider context for its own reconnects, the creation
	// context bounds this creation only and is canceled by a stop of the key or by
	// Cleanup: an aborted creation must not connect to a target which is gone and
	// must not cache the client it built
	p.mu.Lock()
	providerCtx := p.keyedClientsCtx
	creation := p.startKeyedCreation(key, providerCtx)
	client, err := p.buildClient(providerCtx, sess, privateKeys, withStandaloneClientOpts(opts...))
	p.mu.Unlock()

	defer p.finishKeyedCreation(key, creation)

	if err != nil {
		// cleanup removes the dir with written private keys, so build fails with an
		// unrelated error instead of telling the caller that the provider is gone
		if creation.ctx.Err() != nil {
			return nil, abortedDuringCreation(key, providerCtx)
		}

		return nil, fmt.Errorf("create client for key %s: %w", key, err)
	}

	if err := client.Start(creation.ctx); err != nil {
		client.Stop()

		if creation.ctx.Err() != nil {
			return nil, abortedDuringCreation(key, providerCtx)
		}

		return nil, fmt.Errorf("start client for key %s: %w", key, err)
	}

	if !client.Live() {
		client.Stop()
		return nil, fmt.Errorf("client for key %s is not live after start", key)
	}

	p.mu.Lock()

	if creation.ctx.Err() != nil {
		p.mu.Unlock()
		client.Stop()
		return nil, abortedDuringCreation(key, providerCtx)
	}

	p.keyedClients[key] = client
	p.mu.Unlock()

	return client, nil
}

func (p *DefaultSSHProvider) StopStandaloneClientFor(_ context.Context, key string) {
	p.mu.Lock()
	client := p.keyedClients[key]
	delete(p.keyedClients, key)
	creation := p.keyedCreations[key]
	p.mu.Unlock()

	if creation != nil {
		// the creation connects to a target which is gone, abort it and let the next
		// caller for the key start its own instead of joining this one
		p.debug("Aborting client creation for key %s", key)
		creation.cancel()
		p.keyedFlights.Forget(key)
	}

	if govalue.Nil(client) {
		return
	}

	// stop outside the provider lock, stopping a reconnecting client can block
	p.debug("Stopping client for key %s", key)
	client.Stop()
}

// keyedCreation is the creation of a keyed client in flight, kept to abort it
type keyedCreation struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// startKeyedCreation must be called with p.mu held
func (p *DefaultSSHProvider) startKeyedCreation(key string, providerCtx context.Context) *keyedCreation {
	ctx, cancel := context.WithCancel(providerCtx)
	creation := &keyedCreation{ctx: ctx, cancel: cancel}
	p.keyedCreations[key] = creation

	return creation
}

func (p *DefaultSSHProvider) finishKeyedCreation(key string, creation *keyedCreation) {
	p.mu.Lock()
	// a stop of the key forgets the flight, so the registered creation can already
	// belong to another caller
	if p.keyedCreations[key] == creation {
		delete(p.keyedCreations, key)
	}
	p.mu.Unlock()

	creation.cancel()
}

// abortedDuringCreation tells the caller what threw its client away: the whole
// provider was cleaned up or only this key was stopped
func abortedDuringCreation(key string, providerCtx context.Context) error {
	if providerCtx.Err() != nil {
		return fmt.Errorf("%w during client creation for key %s", ErrProviderCleanedUp, key)
	}

	return fmt.Errorf("client for key %s was stopped during creation", key)
}

func (p *DefaultSSHProvider) SwitchClient(ctx context.Context, sess *session.Session, privateKeys []session.AgentPrivateKey) (connection.SSHClient, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.debug("Start switch to new client %s", sess.String())

	p.stopCurrentClientIfNeed()

	client, err := p.createClient(ctx, sess, privateKeys)
	if err != nil {
		return nil, err
	}

	p.currentClient = client

	p.debug("Default client switched to new client %s", sess.String())

	return client, nil
}

func (p *DefaultSSHProvider) SwitchToDefault(ctx context.Context) (connection.SSHClient, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.debug("Start switch client to default settings client")

	p.stopCurrentClientIfNeed()

	// can use doGetCurrentClient because stopCurrentClientIfNeed set currentClient to nil
	// do not use Client because Client acquire lock
	client, err := p.doGetCurrentClient(ctx)
	if err != nil {
		return nil, err
	}

	p.debug("Default client switched to default settings client")

	return client, nil
}

func (p *DefaultSSHProvider) Cleanup(context.Context) error {
	// clients are stopped outside the lock, stopping a reconnecting client blocks
	// until it exhausts the reconnect budget and parks all provider methods
	cleaned := p.resetState()

	var errs *multierror.Error

	if !govalue.Nil(cleaned.currentClient) {
		cleaned.currentClient.Stop()
	}

	for _, client := range cleaned.additionalClients {
		if !govalue.Nil(client) {
			client.Stop()
		}
	}

	for _, client := range cleaned.keyedClients {
		client.Stop()
	}

	if cleaned.privateKeysTmp != "" {
		p.debug("Remove private keys dir %s", cleaned.privateKeysTmp)
		if err := os.RemoveAll(cleaned.privateKeysTmp); err != nil {
			errs = multierror.Append(
				errs,
				fmt.Errorf("Cannot remove private keys dir %s: %w", cleaned.privateKeysTmp, err),
			)
		}
	}

	return errs.ErrorOrNil()
}

type cleanedState struct {
	currentClient     connection.SSHClient
	additionalClients []connection.SSHClient
	keyedClients      map[string]connection.SSHClient
	privateKeysTmp    string
}

// resetState
// drops all clients and prepared private keys from the provider
// and returns them for stopping and removing outside the provider lock
func (p *DefaultSSHProvider) resetState() cleanedState {
	p.mu.Lock()
	defer p.mu.Unlock()

	cleaned := cleanedState{
		currentClient:     p.currentClient,
		additionalClients: p.additionalClients,
		keyedClients:      p.keyedClients,
		privateKeysTmp:    p.privateKeysTmp,
	}

	p.currentClient = nil
	p.additionalClients = nil
	p.keyedClients = make(map[string]connection.SSHClient)

	// cancel before the clients are stopped: a reconnecting client holds its
	// lifecycle lock until the reconnect budget is exhausted and Stop waits for it.
	// creations in flight are children of this context, so they are aborted too and
	// drop their own entries in keyedCreations
	p.keyedClientsCancel()
	p.keyedClientsCtx, p.keyedClientsCancel = context.WithCancel(context.Background())

	// keys written to the removed tmp dir cannot be used by the next clients
	p.privateKeysTmp = ""
	p.privateKeysPrepared = false
	p.writtenPrivateKeys = make([]session.AgentPrivateKey, 0, 2)
	p.defaultPrivateKeysWithPaths = nil

	return cleaned
}

// WithOptions
// warning passed options fully rewrite options passed to NewDefaultSSHProvider
func (p *DefaultSSHProvider) WithOptions(opts ...SSHClientOption) *DefaultSSHProvider {
	p.mu.Lock()
	defer p.mu.Unlock()

	options := SSHClientOptions{
		InitializeNewAgent: true,
	}

	for _, opt := range opts {
		opt(&options)
	}

	p.options = options

	return p
}

func (p *DefaultSSHProvider) WithID(id string) *DefaultSSHProvider {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.options.ClientID = id

	return p
}

// AdditionalClients
// please use for testing purposes only!
func (p *DefaultSSHProvider) AdditionalClients() []connection.SSHClient {
	dest := make([]connection.SSHClient, len(p.additionalClients))
	copy(dest, p.additionalClients)

	return dest
}

func (p *DefaultSSHProvider) HasCurrent() bool {
	return !govalue.Nil(p.currentClient)
}

func (p *DefaultSSHProvider) doGetCurrentClient(ctx context.Context) (connection.SSHClient, error) {
	if !govalue.Nil(p.currentClient) {
		return p.currentClient, nil
	}

	client, err := p.createClient(ctx, nil, nil)
	if err != nil {
		return nil, err
	}

	p.currentClient = client

	return client, nil
}

func (p *DefaultSSHProvider) createClient(ctx context.Context, parent *session.Session, inputPrivateKeys []session.AgentPrivateKey, opts ...createClientOpt) (connection.SSHClient, error) {
	client, err := p.buildClient(ctx, parent, inputPrivateKeys, opts...)
	if err != nil {
		return nil, err
	}

	if p.options.StartClient {
		if err := client.Start(ctx); err != nil {
			client.Stop()
			return nil, fmt.Errorf("start client after create: %w", err)
		}
	}

	return client, nil
}

func (p *DefaultSSHProvider) buildClient(ctx context.Context, parent *session.Session, inputPrivateKeys []session.AgentPrivateKey, opts ...createClientOpt) (connection.SSHClient, error) {
	if !p.defaultConfig.Config.HaveAuthMethods() {
		return nil, fmt.Errorf("Did not any auth methods provided")
	}

	if err := p.prepareConfigPrivateKeys(); err != nil {
		return nil, fmt.Errorf("Cannot prepare private keys: %w", err)
	}

	options := createClientOpts{}
	for _, opt := range opts {
		opt(&options)
	}

	sess, privateKeys, err := p.newSession(parent, inputPrivateKeys, options)
	if err != nil {
		return nil, err
	}

	client := p.constructClient(ctx, sess, privateKeys)
	if govalue.Nil(client) {
		return nil, fmt.Errorf("Cannot create client. Client contructor provide nil object")
	}

	return client, nil
}

func (p *DefaultSSHProvider) constructClient(ctx context.Context, sess *session.Session, privateKeys []session.AgentPrivateKey) connection.SSHClient {
	if p.useGoSSH(true) {
		return gossh.NewClient(ctx, p.sett, sess, privateKeys).
			WithLoopsParams(p.options.LoopsParams).WithID(p.options.ClientID)
	}

	initNewAgent := p.options.InitializeNewAgent
	if p.defaultConfig.Config.ForceUseSSHAgent {
		p.debug("Force no init new agent because ForceUseSSHAgent in default config set")
		initNewAgent = false
	}

	return clissh.NewClient(p.sett, sess, privateKeys, initNewAgent).WithID(p.options.ClientID)
}

func (p *DefaultSSHProvider) stopCurrentClientIfNeed() {
	defer func() {
		p.currentClient = nil
	}()

	if govalue.Nil(p.currentClient) {
		p.debug("CurrentClient is nil, skipping stop current client")
		return
	}

	if !p.useGoSSH(false) {
		// do not need for cli-ssh because cli-ssh initialize agent
		return
	}

	p.debug("Stopping old SSH Client: %s", p.currentClient.Session().String())
	p.currentClient.Stop()

	p.debug("Waiting for '%s' for stopped old SSH client", p.goSSHStopWait.String())
	// todo ugly solution we need to add waiting function after stop in clients
	// wait for keep-alive goroutine will exit
	time.Sleep(p.goSSHStopWait)
}

func (p *DefaultSSHProvider) fillDefaults(input *session.Input, options createClientOpts) {
	if !options.SetSettingsFromDefaultsIfNeeded {
		return
	}

	config := p.defaultConfig.Config

	if input.Port == "" {
		input.Port = config.PortString()
	}

	if input.User == "" {
		input.User = config.User
	}

	if input.BecomePass == "" {
		input.BecomePass = config.SudoPassword
	}

	if input.BastionHost == "" {
		input.BastionHost = config.BastionHost
	}

	if input.BastionUser == "" {
		input.BastionUser = config.BastionUser
	}

	if input.BastionPort == "" {
		input.BastionPort = config.BastionPortString()
	}

	if input.BastionPassword == "" {
		input.BastionPassword = config.BastionPassword
	}

	if input.ExtraArgs == "" {
		input.ExtraArgs = config.ExtraArgs
	}
}

func (p *DefaultSSHProvider) newSession(parent *session.Session, privateKeys []session.AgentPrivateKey, options createClientOpts) (*session.Session, []session.AgentPrivateKey, error) {
	input := session.Input{}
	if parent != nil {
		hosts := parent.AvailableHosts()
		if len(hosts) == 0 {
			return nil, nil, fmt.Errorf("Cannot pass hosts to connection in session")
		}

		input.User = parent.User
		input.Port = parent.Port
		input.BecomePass = parent.BecomePass

		input.BastionHost = parent.BastionHost
		input.BastionPort = parent.BastionPort
		input.BastionUser = parent.BastionUser
		input.BastionPassword = parent.BastionPassword

		input.ExtraArgs = parent.ExtraArgs

		input.AvailableHosts = hosts

		p.fillDefaults(&input, options)
	} else {
		config := p.defaultConfig.Config

		input.User = config.User
		// port not nil here, default config prepared
		input.Port = config.PortString()
		input.BecomePass = config.SudoPassword

		input.BastionHost = config.BastionHost
		// bastion port not nil here, default config prepared
		input.BastionPort = config.BastionPortString()
		input.BastionUser = config.BastionUser
		input.BastionPassword = config.BastionPassword
		input.ExtraArgs = config.ExtraArgs

		hosts := make([]session.Host, 0, len(p.defaultConfig.Hosts))
		for _, h := range p.defaultConfig.Hosts {
			hosts = append(hosts, session.Host{
				Host: h.Host,
				Name: h.Host,
			})
		}

		input.AvailableHosts = hosts
	}

	if len(input.AvailableHosts) == 0 {
		return nil, nil, fmt.Errorf("hosts is empty in session or default config")
	}

	resPrivateKeys := make([]session.AgentPrivateKey, 0, len(privateKeys))
	privateKeysInSession := make(map[string]struct{})

	for _, key := range privateKeys {
		privateKeysInSession[key.Key] = struct{}{}
		resPrivateKeys = append(resPrivateKeys, key)
	}

	// add keys from config because we can use bastion and bastion key
	// presents only in config if switch client
	for _, writtenKey := range p.writtenPrivateKeys {
		if _, ok := privateKeysInSession[writtenKey.Key]; !ok {
			resPrivateKeys = append(resPrivateKeys, writtenKey)
		}
	}

	for _, keysWithPath := range p.defaultPrivateKeysWithPaths {
		if _, ok := privateKeysInSession[keysWithPath.Key]; !ok {
			resPrivateKeys = append(resPrivateKeys, keysWithPath)
		}
	}

	return session.NewSession(input), resPrivateKeys, nil
}

func (p *DefaultSSHProvider) useGoSSH(shouldLog bool) bool {
	logDebug := func(format string) {
		if !shouldLog {
			return
		}

		p.debug("%s", format)
	}

	if p.options.ForceGoSSH {
		logDebug("Force go-ssh client from provider options")
		return true
	}

	config := p.defaultConfig.Config

	if config.ForceModern {
		logDebug("Force go-ssh client from client settings")
		return true
	}

	if config.ForceLegacy {
		logDebug("Force cli-ssh from client settings")
		return false
	}

	logDebug("Use go-ssh by default")
	return true
}

func (p *DefaultSSHProvider) prepareConfigPrivateKeys() error {
	if p.privateKeysPrepared {
		return nil
	}

	var keysToWrite []sshconfig.AgentPrivateKey
	for _, key := range p.defaultConfig.Config.PrivateKeys {
		if !key.IsPath {
			keysToWrite = append(keysToWrite, key)
			continue
		}

		if err := p.appendPrivateKeyPath(key); err != nil {
			return err
		}
	}

	if len(keysToWrite) == 0 {
		p.privateKeysPrepared = true
		return nil
	}

	if err := p.createPrivateKeysDir(); err != nil {
		return err
	}

	for _, key := range keysToWrite {
		if err := p.writeKey(key); err != nil {
			return err
		}
	}

	p.privateKeysPrepared = true

	return nil
}

func (p *DefaultSSHProvider) appendPrivateKeyPath(key sshconfig.AgentPrivateKey) error {
	path := key.Key

	var err error
	path, err = file.FullPath(path, "private key")
	if err != nil {
		return err
	}

	if err := file.IsExists(path, "private key"); err != nil {
		return err
	}

	p.defaultPrivateKeysWithPaths = append(p.defaultPrivateKeysWithPaths, session.AgentPrivateKey{
		Key:        path,
		Passphrase: key.Passphrase,
	})

	return nil
}

func (p *DefaultSSHProvider) writeKey(key sshconfig.AgentPrivateKey) error {
	if p.privateKeysTmp == "" {
		return fmt.Errorf("internal error: tmp dir for private keys did not created")
	}

	keyFullPath, err := p.keyPath()
	if err != nil {
		return err
	}

	p.debug("Writing private key %s", keyFullPath)

	content := []byte(key.Key)

	if err := os.WriteFile(keyFullPath, content, 0600); err != nil {
		return fmt.Errorf("cannot write private key to file %s: %w", keyFullPath, err)
	}

	p.writtenPrivateKeys = append(p.writtenPrivateKeys, session.AgentPrivateKey{
		Key:        keyFullPath,
		Passphrase: key.Passphrase,
	})

	p.debug("Private key written to %s", keyFullPath)

	return nil
}

func (p *DefaultSSHProvider) createPrivateKeysDir() error {
	if p.privateKeysTmp != "" {
		return nil
	}
	subDir := randString()
	tmpDir := filepath.Join(p.sett.TmpDir(), "lib-connection-ssh", subDir)
	err := os.MkdirAll(tmpDir, 0755)
	if err != nil {
		return fmt.Errorf("cannot create private keys tmp dir: %w", err)
	}

	p.privateKeysTmp = tmpDir
	p.debug("Private keys tmp dir %s created", p.privateKeysTmp)

	return nil
}

func (p *DefaultSSHProvider) keyPath() (string, error) {
	if p.privateKeysTmp == "" {
		return "", fmt.Errorf("Internal error. Private keys tmp dir is empty")
	}

	const attempts = 100

	for i := 0; i < attempts; i++ {
		keyName := fmt.Sprintf("pk.%s", randString())
		path := filepath.Join(p.privateKeysTmp, keyName)

		exists, err := fileExists(path)
		if err != nil {
			return "", err
		}

		if !exists {
			return path, nil
		}

		p.debug("Generated private key path failed, attempt %d", i)
	}

	return "", fmt.Errorf("Failed to generate private keys tmp dir, all attempts %d failed", attempts)
}

func (p *DefaultSSHProvider) debug(format string, args ...any) {
	p.sett.Logger().DebugContext(context.Background(), fmt.Sprintf(format, args...))
}

type createClientOpts struct {
	connection.StandaloneClientOpts
}

type createClientOpt func(*createClientOpts)

func withStandaloneClientOpts(opts ...connection.StandaloneClientOpt) createClientOpt {
	return func(create *createClientOpts) {
		standalone := connection.StandaloneClientOpts{}
		for _, o := range opts {
			o(&standalone)
		}

		create.StandaloneClientOpts = standalone
	}
}

func randString() string {
	randomizer := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	return fmt.Sprintf("%d", randomizer.Uint32())
}

func fileExists(path string) (bool, error) {
	stat, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}

		return false, fmt.Errorf("Cannot stat path %s: %w", path, err)
	}

	if stat.IsDir() || !stat.Mode().IsRegular() {
		return false, fmt.Errorf("path %s not regular file", path)
	}

	return true, nil
}

type ErrorSSHProvider struct {
	err error
}

var ErrSSHClientCannotProvided = errors.New("cannot provide ssh client")

// NewErrorSSHProvider
// Special provider that always return error for all operations
// expected cleanup
// it can be used with GetRunnerInterface if you are you sure that
// you do not use KubeClient over SSH
func NewErrorSSHProvider(err error) *ErrorSSHProvider {
	if err == nil {
		err = fmt.Errorf("%w ErrorSSHProvider: error not provided", ErrSSHClientCannotProvided)
	}
	return &ErrorSSHProvider{err: err}
}

func (p *ErrorSSHProvider) Client(context.Context) (connection.SSHClient, error) {
	return nil, p.returnError("Client")
}

func (p *ErrorSSHProvider) NewAdditionalClient(context.Context) (connection.SSHClient, error) {
	return nil, p.returnError("NewAdditionalClient")
}

func (p *ErrorSSHProvider) NewStandaloneClient(context.Context, *session.Session, []session.AgentPrivateKey, ...connection.StandaloneClientOpt) (connection.SSHClient, error) {
	return nil, p.returnError("NewStandaloneClient")
}

func (p *ErrorSSHProvider) StandaloneClientFor(context.Context, string, *session.Session, []session.AgentPrivateKey, ...connection.StandaloneClientOpt) (connection.SSHClient, error) {
	return nil, p.returnError("StandaloneClientFor")
}

func (p *ErrorSSHProvider) StopStandaloneClientFor(context.Context, string) {}

func (p *ErrorSSHProvider) SwitchClient(context.Context, *session.Session, []session.AgentPrivateKey) (connection.SSHClient, error) {
	return nil, p.returnError("SwitchClient")
}

func (p *ErrorSSHProvider) SwitchToDefault(context.Context) (connection.SSHClient, error) {
	return nil, p.returnError("SwitchToDefault")
}

func (p *ErrorSSHProvider) Cleanup(context.Context) error {
	return nil
}

func (p *ErrorSSHProvider) returnError(op string) error {
	return fmt.Errorf("%w with %s: %w", ErrSSHClientCannotProvided, op, p.err)
}
