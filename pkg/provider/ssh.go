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
	"crypto/sha256"
	"fmt"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/name212/govalue"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/clissh"
	sshconfig "github.com/deckhouse/lib-connection/pkg/ssh/config"
	"github.com/deckhouse/lib-connection/pkg/ssh/gossh"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
)

type DefaultSSHProvider struct {
	mu sync.Mutex

	defaultConfig *sshconfig.ConnectionConfig

	currentClient     connection.SSHClient
	additionalClients []connection.SSHClient

	sett settings.Settings

	privateKeysTmp      string
	writtenPrivateKeys  []alreadyWrittenKey
	privateKeysPrepared bool

	cleaned bool
}

func NewDefaultSSHProvider(sett settings.Settings, config *sshconfig.ConnectionConfig) *DefaultSSHProvider {
	clonedConfig := config.Config.Clone().FillDefaults()
	clonedConnectionConfig := &sshconfig.ConnectionConfig{
		Hosts:  config.Hosts,
		Config: clonedConfig,
	}

	return &DefaultSSHProvider{
		defaultConfig:      clonedConnectionConfig,
		sett:               sett,
		writtenPrivateKeys: make([]alreadyWrittenKey, 0, 2),
	}
}

func NewDefaultSSHProviderFromFlags(sett settings.Settings, flags *sshconfig.Flags, opts ...sshconfig.ValidateOption) (*DefaultSSHProvider, error) {
	parser := sshconfig.NewFlagsParser(sett)
	config, err := parser.ExtractConfigAfterParse(flags, opts...)
	if err != nil {
		return nil, err
	}

	return NewDefaultSSHProvider(sett, config), nil
}

func (p *DefaultSSHProvider) NewClient(ctx context.Context, opts ...connection.SSHClientOption) (connection.SSHClient, error) {
	client, err := p.createClient(ctx, nil, nil, opts...)
	if err != nil {
		return nil, err
	}

	p.additionalClients = append(p.additionalClients, client)
	return client, nil
}

func (p *DefaultSSHProvider) Client(ctx context.Context, opts ...connection.SSHClientOption) (connection.SSHClient, error) {
	if !govalue.Nil(p.currentClient) {
		return p.currentClient, nil
	}

	client, err := p.createClient(ctx, nil, nil, opts...)
	if err != nil {
		return nil, err
	}

	p.currentClient = client

	return client, nil
}

func (p *DefaultSSHProvider) SwitchClient(ctx context.Context, sess *session.Session, privateKeys []session.AgentPrivateKey) (connection.SSHClient, error) {
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
	p.debug("Start switch to default settings client")

	p.stopCurrentClientIfNeed()

	// can use Client because stopCurrentClientIfNeed set currentClient to nil
	client, err := p.Client(ctx)
	if err != nil {
		return nil, err
	}

	p.debug("Default client switched to default settings client")

	return client, nil
}

func (p *DefaultSSHProvider) Cleanup(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var errs *multierror.Error

	if !govalue.Nil(p.currentClient) {
		p.currentClient.Stop()
		p.currentClient = nil
	}

	for _, client := range p.additionalClients {
		if !govalue.Nil(client) {
			client.Stop()
		}
	}

	p.additionalClients = nil

	privateKeysTmp := p.privateKeysTmp

	if privateKeysTmp != "" {
		if err := os.RemoveAll(privateKeysTmp); err != nil {
			errs = multierror.Append(
				errs,
				fmt.Errorf("Cannot remove private keys dir %s: %w", privateKeysTmp, err),
			)
		}
	}

	return errs.ErrorOrNil()
}

func (p *DefaultSSHProvider) createClient(ctx context.Context, parent *session.Session, inputPrivateKeys []session.AgentPrivateKey, opts ...connection.SSHClientOption) (connection.SSHClient, error) {
	if err := p.prepareConfigPrivateKeys(); err != nil {
		return nil, fmt.Errorf("Cannot prepare private keys: %w", err)
	}

	sess, privateKeys := p.newSession(parent, inputPrivateKeys)

	if p.useGoSSH() {
		return gossh.NewClient(ctx, p.sett, sess, privateKeys), nil
	}

	options := connection.SSHClientOptions{}
	for _, opt := range opts {
		opt(&options)
	}

	return clissh.NewClient(p.sett, sess, privateKeys, options.InitializeNewAgent), nil
}

func (p *DefaultSSHProvider) stopCurrentClientIfNeed() {
	if govalue.Nil(p.currentClient) {
		p.debug("CurrentClient is nil, skipping stop current client")
		return
	}

	defer func() {
		p.currentClient = nil
	}()

	if !p.useGoSSH() {
		// do not need cli-ssh
		return
	}

	p.debug("Stopping old SSH Client: %-v\n", p.currentClient)
	p.currentClient.Stop()

	sleep := 10 * time.Second
	p.debug("Waiting for '%s' for stopped old SSH client\n", sleep)
	// todo ugly solution we need to add waiting function after stop in clients
	// wait for keep-alive goroutine will exit
	time.Sleep(sleep)
}

func (p *DefaultSSHProvider) newSession(parent *session.Session, privateKeys []session.AgentPrivateKey) (*session.Session, []session.AgentPrivateKey) {
	input := session.Input{}
	if parent != nil {
		input.User = parent.User
		input.Port = parent.Port
		input.BecomePass = parent.BecomePass

		input.BastionHost = parent.BastionHost
		input.BastionPort = parent.BastionPort
		input.BastionUser = parent.BastionUser
		input.BastionPassword = parent.BastionPassword

		input.ExtraArgs = parent.ExtraArgs

		input.AvailableHosts = parent.AvailableHosts()
	} else {
		config := p.defaultConfig.Config

		input.User = config.User
		// port not nil here, default config prepared
		input.Port = fmt.Sprint(*config.Port)
		input.BecomePass = config.SudoPassword

		input.BastionHost = config.BastionHost
		// bastion port not nil here, default config prepared
		input.BastionPort = fmt.Sprint(*config.BastionPort)
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

	resPrivateKeys := make([]session.AgentPrivateKey, 0, len(privateKeys))
	privateKeysInSession := make(map[string]struct{})

	for _, key := range privateKeys {
		privateKeysInSession[key.Key] = struct{}{}
		resPrivateKeys = append(resPrivateKeys, key)
	}

	// add keys from config because we can use bastion and bastion key
	// presents only in config if switch client
	for _, writtenKey := range p.writtenPrivateKeys {
		if _, ok := privateKeysInSession[writtenKey.key.Key]; !ok {
			resPrivateKeys = append(resPrivateKeys, writtenKey.key)
		}
	}

	return session.NewSession(input), resPrivateKeys
}

func (p *DefaultSSHProvider) useGoSSH() bool {
	config := p.defaultConfig.Config

	if config.ForceModern {
		p.debug("Force go-ssh client from client")
		return true
	}

	if config.ForceLegacy {
		p.debug("Force cli-ssh from client")
		return false
	}

	// if passed private keys force cli
	// if use password auth use gossh
	if len(config.PrivateKeys) == 0 {
		p.debug("Force go-ssh client because use password auth. cli-ssh does not support password auth")
		return true
	}

	p.debug("Use cli-ssh by default")
	return false
}

func (p *DefaultSSHProvider) prepareConfigPrivateKeys() error {
	if p.privateKeysPrepared {
		return nil
	}

	var res []session.AgentPrivateKey

	var keysToWrite []sshconfig.AgentPrivateKey
	for _, key := range p.defaultConfig.Config.PrivateKeys {
		if !key.IsPath {
			keysToWrite = p.appendKeyToWrite(key, keysToWrite)
			continue
		}

		var err error
		res, err = p.appendPrivateKeyPath(key, res)
		if err != nil {
			return err
		}
	}

	if len(keysToWrite) == 0 {
		return nil
	}

	if err := p.createPrivateKeysDir(); err != nil {
		return err
	}

	for _, key := range keysToWrite {
		var err error
		res, err = p.writeKey(key, res)
		if err != nil {
			return err
		}
	}

	p.privateKeysPrepared = true

	return nil
}

func (p *DefaultSSHProvider) appendKeyToWrite(key sshconfig.AgentPrivateKey, keysToWrite []sshconfig.AgentPrivateKey) []sshconfig.AgentPrivateKey {
	isWritten := false
	for _, w := range p.writtenPrivateKeys {
		if key.Key == w.key.Key {
			continue
		}

		isWritten = w.contentSum == shaSum([]byte(key.Key))
	}

	if !isWritten {
		keysToWrite = append(keysToWrite, key)
	}

	return keysToWrite
}

func (p *DefaultSSHProvider) appendPrivateKeyPath(key sshconfig.AgentPrivateKey, res []session.AgentPrivateKey) ([]session.AgentPrivateKey, error) {
	path := key.Key

	exists, err := fileExists(path)
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, fmt.Errorf("private key %s does not exist", path)
	}

	res = append(res, session.AgentPrivateKey{
		Key:        key.Key,
		Passphrase: key.Passphrase,
	})

	return res, nil
}

func (p *DefaultSSHProvider) writeKey(key sshconfig.AgentPrivateKey, res []session.AgentPrivateKey) ([]session.AgentPrivateKey, error) {
	if p.privateKeysTmp == "" {
		return nil, fmt.Errorf("internal error: tmp dir for private keys did not created")
	}

	keyFullPath, err := p.keyPath()
	if err != nil {
		return nil, err
	}

	p.debug("Writing private key %s", keyFullPath)

	content := []byte(key.Key)

	if err := os.WriteFile(keyFullPath, content, 0600); err != nil {
		return nil, fmt.Errorf("cannot write private key to file %s: %w", keyFullPath, err)
	}

	writtenAgentKey := session.AgentPrivateKey{
		Key:        keyFullPath,
		Passphrase: key.Passphrase,
	}

	writtenKey := alreadyWrittenKey{
		key:        writtenAgentKey,
		contentSum: shaSum(content),
	}

	p.writtenPrivateKeys = append(p.writtenPrivateKeys, writtenKey)
	res = append(res, writtenAgentKey)

	p.debug("Private key written to %s", keyFullPath)

	return res, nil
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
	p.sett.Logger().DebugF(format, args...)
}

type alreadyWrittenKey struct {
	key        session.AgentPrivateKey
	contentSum string
}

func shaSum(input []byte) string {
	hasher := sha256.New()

	hasher.Write(input)

	return fmt.Sprintf("%x", hasher.Sum(nil))
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

	if stat.IsDir() {
		return false, fmt.Errorf("Path %s is a directory", path)
	}

	return true, nil
}
