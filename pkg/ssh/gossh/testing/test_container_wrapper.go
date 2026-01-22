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

package ssh_testing

import (
	"testing"

	"github.com/name212/govalue"
	"github.com/stretchr/testify/require"

	"github.com/deckhouse/lib-connection/pkg/ssh/session"
)

type TestContainerWrapperSettingsOpts func(container *TestContainerWrapperSettings)
type TestContainerWrapperSettings struct {
	*ContainerSettings

	PrivateKeyPassword string
	ExternalNetwork    string

	NoStartContainerDuringCreate          bool
	NoWaitStartingSSHDAfterStartContainer bool
	NoGeneratePrivateKey                  bool
	NoWriteSSHDConfig                     bool
}

type TestContainerWrapper struct {
	Container      *SSHContainer
	Settings       *TestContainerWrapperSettings
	PrivateKeyPath string
}

func NewTestContainerWrapper(t *testing.T, test *Test, opts ...TestContainerWrapperSettingsOpts) *TestContainerWrapper {
	require.False(t, govalue.Nil(test), "test must not be nil")

	testSettings := &TestContainerWrapperSettings{
		ContainerSettings: &ContainerSettings{
			Test:        test,
			Password:    RandPassword(12),
			Username:    "user",
			SudoAccess:  true,
			NodeTmpPath: "/opt/deckhouse/tmp",
		},
	}

	for _, opt := range opts {
		opt(testSettings)
	}

	testContainer := &TestContainerWrapper{
		Settings: testSettings,
	}

	if !testSettings.HasPublicKeyContent() || !testSettings.HasPublicKeyPath() {
		privateKeyPath, publicKey, err := GenerateKeys(test, testSettings.PrivateKeyPassword)
		if err != nil {
			testContainer.Cleanup(t)
			require.NoError(t, err)
		}

		publicKeyPath, err := WritePubKeyFileForPrivate(test, privateKeyPath, publicKey)
		if err != nil {
			testContainer.Cleanup(t)
			require.NoError(t, err)
		}

		test.Logger.DebugF("Private key created: path '%s' pub key path: %s", privateKeyPath, publicKeyPath)

		testSettings.PublicKey = &PublicKey{
			Path: publicKeyPath,
			Key:  publicKey,
		}
		testContainer.PrivateKeyPath = privateKeyPath
	}

	container, err := NewSSHContainer(testSettings.ContainerSettings)
	require.NoError(t, err)

	testContainer.Container = container
	t.Cleanup(func() {
		testContainer.Cleanup(t)
	})

	if testSettings.ExternalNetwork != "" {
		container.WithExternalNetwork(testSettings.ExternalNetwork)
	}

	if !testSettings.NoWriteSSHDConfig {
		err := container.WriteConfig()
		require.NoError(t, err)
	}

	if !testSettings.NoStartContainerDuringCreate {
		wait := !testSettings.NoWaitStartingSSHDAfterStartContainer
		err = container.Start(wait)
		require.NoError(t, err)
	}

	return testContainer
}

func (c *TestContainerWrapper) LocalPort() int {
	return c.Container.ContainerSettings().LocalPort
}

func (c *TestContainerWrapper) ContainerIP() string {
	return c.Container.GetContainerIP()
}

func (c *TestContainerWrapper) AgentPrivateKeys() []session.AgentPrivateKey {
	if !c.Settings.HasPublicKey() || !c.Settings.HasPublicKeyPath() {
		return make([]session.AgentPrivateKey, 0, 1)
	}

	return []session.AgentPrivateKey{{Key: c.PrivateKeyPath, Passphrase: c.Settings.PrivateKeyPassword}}
}

func (c *TestContainerWrapper) PublicKeyPath() string {
	if c.Settings.HasPublicKeyPath() {
		return c.Settings.PublicKey.Path
	}

	return ""
}

func (c *TestContainerWrapper) Cleanup(t *testing.T) {
	containerStopError := c.Container.Stop()
	removeErrors := removeFiles(c.PrivateKeyPath, c.PublicKeyPath(), c.Container.GetSSHDConfigPath())

	logger := c.Settings.Test.Logger

	LogErrorOrAssert(t, "failed to stop container", containerStopError, logger)
	for _, removeError := range removeErrors {
		LogErrorOrAssert(t, "failed to remove private key", removeError, logger)
	}

	c.Settings.Cleanup(t)
}

func WithNoStartContainer() TestContainerWrapperSettingsOpts {
	return func(s *TestContainerWrapperSettings) {
		s.NoStartContainerDuringCreate = true
	}
}

func WithNoWriteSSHDConfig() TestContainerWrapperSettingsOpts {
	return func(s *TestContainerWrapperSettings) {
		s.NoWriteSSHDConfig = true
	}
}

func WithUserName(name string) TestContainerWrapperSettingsOpts {
	return func(s *TestContainerWrapperSettings) {
		s.Username = name
	}
}

func WithConnectToContainerNetwork(testContainer *TestContainerWrapper) TestContainerWrapperSettingsOpts {
	return func(s *TestContainerWrapperSettings) {
		s.ExternalNetwork = testContainer.Container.GetNetwork()
	}
}

func WithAuthSettings(testContainer *TestContainerWrapper) TestContainerWrapperSettingsOpts {
	return func(s *TestContainerWrapperSettings) {
		s.ContainerSettings.Password = testContainer.Settings.Password
		s.ContainerSettings.PublicKey = testContainer.Settings.PublicKey
	}
}

func WithNoWaitStartingSSHDAfterStartContainer() TestContainerWrapperSettingsOpts {
	return func(s *TestContainerWrapperSettings) {
		s.NoWaitStartingSSHDAfterStartContainer = true
	}
}

func WithNoPassword() TestContainerWrapperSettingsOpts {
	return func(s *TestContainerWrapperSettings) {
		s.ContainerSettings.Password = ""
	}
}

func WithPassword(password string) TestContainerWrapperSettingsOpts {
	return func(s *TestContainerWrapperSettings) {
		s.ContainerSettings.Password = password
	}
}

func WithContainerName(name string) TestContainerWrapperSettingsOpts {
	return func(s *TestContainerWrapperSettings) {
		s.ContainerSettings.ContainerName = name
	}
}

func WithNoSudo() TestContainerWrapperSettingsOpts {
	return func(s *TestContainerWrapperSettings) {
		s.ContainerSettings.SudoAccess = false
	}
}

func WithLocalPort(port int) TestContainerWrapperSettingsOpts {
	return func(s *TestContainerWrapperSettings) {
		s.ContainerSettings.LocalPort = port
	}
}
