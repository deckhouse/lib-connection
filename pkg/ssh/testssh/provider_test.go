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

package testssh

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/retry"
	"github.com/stretchr/testify/require"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/provider"
	sshconfig "github.com/deckhouse/lib-connection/pkg/ssh/config"
	"github.com/deckhouse/lib-connection/pkg/ssh/gossh"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
	"github.com/deckhouse/lib-connection/pkg/tests"
)

func TestSSHProviderClientConnect(t *testing.T) {
	runTests := []runTest{
		{
			name: "Go",
			mode: sshconfig.Mode{
				ForceModern: true,
			},
		},

		{
			name: "Cli",
			mode: sshconfig.Mode{
				ForceLegacy: true,
			},
		},
	}

	t.Run("Client", func(t *testing.T) {
		for _, tst := range runTests {
			t.Run(tst.name, func(t *testing.T) {
				test := newTest(t, tst)

				scripName := fmt.Sprintf("client-%s-ssh", strings.ToLower(tst.name))
				container, expectedOut, remotePath := prepareContainer(t, test, scripName)
				config := connectionConfigForContainer(container, tst.mode)

				ctx := context.TODO()

				p := getProvider(test, config)

				client, err := p.Client(ctx)
				require.NoError(t, err)

				registerCleanup(t, test, p)

				assertRunScript(t, assertRunScriptParams{
					client:      client,
					expectedOut: expectedOut,
					executePath: remotePath,
					test:        test,
				})
			})
		}
	})

	t.Run("NewAdditionalClient", func(t *testing.T) {
		for _, tst := range runTests {
			t.Run(tst.name, func(t *testing.T) {
				test := newTest(t, tst)
				scripName := fmt.Sprintf("client-%s-ssh", strings.ToLower(tst.name))
				container, expectedOut, remotePath := prepareContainer(t, test, scripName)
				config := connectionConfigForContainer(container, tst.mode)

				ctx := context.TODO()

				p := getProvider(test, config)

				allClients := make([]connection.SSHClient, 0, 3)

				defaultClient, err := p.Client(ctx)
				require.NoError(t, err, "default client should provided")

				allClients = append(allClients, defaultClient)

				for i := 0; i < 2; i++ {
					client, err := p.NewAdditionalClient(ctx)
					require.NoError(t, err, "")

					allClients = append(allClients, client)
				}

				registerCleanup(t, test, p)

				require.False(t, defaultClient.IsStopped(), "default client should not be stopped")

				for _, client := range allClients {
					assertRunScript(t, assertRunScriptParams{
						client:      client,
						expectedOut: expectedOut,
						executePath: remotePath,
						test:        test,
					})
				}
			})
		}
	})

	t.Run("SwitchClient and SwitchToDefault", func(t *testing.T) {
		for _, tst := range runTests {
			t.Run(tst.name, func(t *testing.T) {
				test := newTest(t, tst)

				tstNoPrivateKey := tst
				tstNoPrivateKey.noUsePrivateKey = true
				main := startContainerWithAnother(t, startContainerWithAnotherParams{
					test:             test,
					containerName:    "main",
					rt:               tstNoPrivateKey,
					anotherContainer: nil,
				})

				switchContainer := startContainerWithAnother(t, startContainerWithAnotherParams{
					test:             test,
					containerName:    "switch",
					rt:               tst,
					anotherContainer: main.container,
				})

				ctx := context.TODO()

				p := getProvider(test, main.config)

				registerCleanup(t, test, p)

				mainAssertParams := func(c connection.SSHClient) assertRunScriptParams {
					return assertRunScriptParams{
						client:      c,
						expectedOut: main.out,
						executePath: main.remote,
						test:        test,
					}
				}

				switchAssertParams := func(c connection.SSHClient) assertRunScriptParams {
					return assertRunScriptParams{
						client:      c,
						expectedOut: switchContainer.out,
						executePath: switchContainer.remote,
						test:        test,
					}
				}

				client, err := p.Client(ctx)
				require.NoError(t, err)

				assertRunScript(t, mainAssertParams(client))

				// check that connect to additional after switch
				additionalAsserts := make([]assertRunScriptParams, 0, 3)

				defaultAdditionalClient, err := p.NewAdditionalClient(ctx)
				require.NoError(t, err, "default additional client should provided")
				additionalAsserts = append(additionalAsserts, mainAssertParams(defaultAdditionalClient))

				sess, privateKeys := sessionForConnectionConfig(switchContainer.config)

				switchedClient, err := p.SwitchClient(ctx, sess, privateKeys)
				require.NoError(t, err, "should switch client")

				assertRunScript(t, switchAssertParams(switchedClient))

				switchedAdditionalClient, err := p.NewAdditionalClient(ctx)
				require.NoError(t, err, "default additional client should provided")
				additionalAsserts = append(additionalAsserts, switchAssertParams(switchedAdditionalClient))

				switchedToDefaultClient, err := p.SwitchToDefault(ctx)
				require.NoError(t, err, "should switch client")

				switchedToDefaultAdditionalClient, err := p.NewAdditionalClient(ctx)
				require.NoError(t, err, "default additional client should provided")
				additionalAsserts = append(additionalAsserts, mainAssertParams(switchedToDefaultAdditionalClient))

				assertRunScript(t, mainAssertParams(switchedToDefaultClient))

				for _, additionalAssert := range additionalAsserts {
					assertRunScript(t, additionalAssert)
				}

				// check invalid run to different containers
				incorrectRunAsserts := []assertRunScriptParams{
					switchAssertParams(defaultAdditionalClient).shouldError(),
					mainAssertParams(switchedClient).shouldError(),
					switchAssertParams(switchedToDefaultAdditionalClient).shouldError(),
				}

				for _, incorrectAssert := range incorrectRunAsserts {
					assertRunScript(t, incorrectAssert)
				}
			})
		}
	})
}

func newTest(t *testing.T, rt runTest) *tests.Test {
	nameParts := strings.Split(t.Name(), "/")
	name := nameParts[len(nameParts)-2]
	name = fmt.Sprintf("ProviderConnect%s%sSSH", name, rt.name)

	return tests.ShouldNewTest(
		t,
		name,
		tests.TestWithParallelRun(true),
	)
}

func prepareContainer(t *testing.T, test *tests.Test, scriptName string, opts ...tests.TestContainerWrapperSettingsOpts) (*tests.TestContainerWrapper, string, string) {
	printStr := fmt.Sprintf("Run %s successfully", scriptName)

	script := fmt.Sprintf(`
#!/bin/bash

echo -n "%s"
`, printStr)

	scriptLocalPath := test.MustCreateTmpFile(t, script, true, scriptName)
	remotePath := fmt.Sprintf("/tmp/%s", scriptName)

	cOpts := []tests.TestContainerWrapperSettingsOpts{
		tests.WithVolumes([]tests.Volume{
			{
				Local:  scriptLocalPath,
				Remote: remotePath,
			},
		}),
	}

	cOpts = append(cOpts, opts...)

	return tests.NewTestContainerWrapper(t, test, cOpts...), printStr, remotePath
}

func connectionConfigForContainer(container *tests.TestContainerWrapper, mode sshconfig.Mode) *sshconfig.ConnectionConfig {
	containerPrivateKeys := container.AgentPrivateKeys()
	privateKeys := make([]sshconfig.AgentPrivateKey, 0, len(containerPrivateKeys))
	for _, key := range containerPrivateKeys {
		privateKeys = append(privateKeys, sshconfig.AgentPrivateKey{
			Key:        key.Key,
			Passphrase: key.Passphrase,
			IsPath:     true,
		})
	}

	return &sshconfig.ConnectionConfig{
		Config: &sshconfig.Config{
			Mode: mode,

			User:         container.Settings.Username,
			Port:         tests.Ptr(container.LocalPort()),
			SudoPassword: container.Settings.Password,

			PrivateKeys: privateKeys,
		},

		Hosts: []sshconfig.Host{
			{
				Host: "127.0.0.1",
			},
		},
	}
}

func sessionForConnectionConfig(config *sshconfig.ConnectionConfig) (*session.Session, []session.AgentPrivateKey) {
	privateKeys := make([]session.AgentPrivateKey, 0, len(config.Config.PrivateKeys))
	for _, key := range config.Config.PrivateKeys {
		privateKeys = append(privateKeys, session.AgentPrivateKey{
			Key:        key.Key,
			Passphrase: key.Passphrase,
		})
	}

	hosts := make([]session.Host, 0, len(config.Hosts))
	for _, host := range config.Hosts {
		hosts = append(hosts, session.Host{
			Host: host.Host,
			Name: host.Host,
		})
	}

	return session.NewSession(session.Input{
		User:       config.Config.User,
		Port:       config.Config.PortString(),
		BecomePass: config.Config.SudoPassword,

		AvailableHosts: hosts,
	}), privateKeys
}

func registerCleanup(t *testing.T, test *tests.Test, p *provider.DefaultSSHProvider) {
	t.Cleanup(func() {
		if err := p.Cleanup(context.TODO()); err != nil {
			test.GetLogger().ErrorF("Failed to clean up %s provider: %v", t.Name(), err)
		}
	})
}

type assertRunScriptParams struct {
	client      connection.SSHClient
	expectedOut string
	executePath string
	test        *tests.Test
}

func (p assertRunScriptParams) shouldError() assertRunScriptParams {
	p.expectedOut = ""
	return p
}

func assertRunScript(t *testing.T, params assertRunScriptParams) {
	ctx, cancel := context.WithTimeout(context.TODO(), 20*time.Second)
	defer cancel()

	var out []byte

	err := retry.NewLoopWithParams(retry.NewEmptyParams(
		retry.WithAttempts(4),
		retry.WithWait(2*time.Second),
		retry.WithName("Run script %s", params.executePath),
		retry.WithLogger(params.test.GetLogger()),
	)).RunContext(ctx, func() error {
		var err error
		cmd := params.client.Command(params.executePath)
		outt, err := cmd.CombinedOutput(ctx)
		if err != nil {
			return err
		}

		out = outt
		return nil
	})

	if params.expectedOut == "" {
		require.Error(t, err, "command should not run")
		return
	}

	strOut := string(out)

	require.NoError(t, err, "command should run")
	require.Contains(t, strOut, params.expectedOut, "have correct output")

	params.test.GetLogger().InfoF("Got output for %s: %s", params.executePath, strOut)
}

func getProvider(test *tests.Test, config *sshconfig.ConnectionConfig) *provider.DefaultSSHProvider {
	defaultLoopParam := retry.NewEmptyParams(
		retry.WithWait(2*time.Second),
		retry.WithAttempts(10),
	)

	loopsParams := gossh.ClientLoopsParams{
		ConnectToHostDirectly: defaultLoopParam.Clone(),
		NewSession:            defaultLoopParam.Clone(),
	}

	return provider.NewDefaultSSHProvider(
		test.Settings(),
		config,
		provider.SSHClientWithLoopsParams(loopsParams),
		provider.SSHClientWithStartAfterCreate(true),
	)
}

type runTest struct {
	mode            sshconfig.Mode
	name            string
	noUsePrivateKey bool
}

type startContainerWithAnotherParams struct {
	test             *tests.Test
	containerName    string
	rt               runTest
	anotherContainer *tests.TestContainerWrapper
}

type containerWithAnother struct {
	out       string
	config    *sshconfig.ConnectionConfig
	remote    string
	container *tests.TestContainerWrapper
}

func startContainerWithAnother(t *testing.T, params startContainerWithAnotherParams) *containerWithAnother {
	rt := params.rt
	containerName := params.containerName

	scripName := fmt.Sprintf("%s-%s-ssh", containerName, strings.ToLower(rt.name))

	opts := []tests.TestContainerWrapperSettingsOpts{
		tests.WithContainerName(containerName),
	}

	if rt.noUsePrivateKey {
		opts = append(opts, tests.WithNoGeneratePrivateKeys())
	}

	if params.anotherContainer != nil {
		opts = append(opts, tests.WithConnectToContainerNetwork(params.anotherContainer))
	}

	container, expectedOut, remotePath := prepareContainer(t, params.test, scripName, opts...)

	config := connectionConfigForContainer(container, rt.mode)

	return &containerWithAnother{
		out:       expectedOut,
		config:    config,
		remote:    remotePath,
		container: container,
	}
}
