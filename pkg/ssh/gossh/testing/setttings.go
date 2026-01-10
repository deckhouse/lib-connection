// Copyright 2025 Flant JSC
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
	"strconv"

	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
	"github.com/deckhouse/lib-dhctl/pkg/log"
)

func TestLogger() *log.InMemoryLogger {
	return log.NewInMemoryLoggerWithParent(log.NewPrettyLogger(log.LoggerOptions{IsDebug: false}))
}

func getDefaultParams(test *Test) settings.ProviderParams {
	return settings.ProviderParams{
		LoggerProvider: log.SimpleLoggerProvider(test.Logger),
		IsDebug:        true,
	}
}

func CreateDefaultTestSettings(test *Test) settings.Settings {
	return settings.NewBaseProviders(getDefaultParams(test))
}

func CreateDefaultTestSettingsWithAgent(test *Test, agentSockPath string) settings.Settings {
	params := getDefaultParams(test)
	params.AuthSock = agentSockPath
	return settings.NewBaseProviders(params)
}

type SessionOverride func(input *session.Input)

func OverrideSessionWithIncorrectPort(wrappers ...*TestContainerWrapper) SessionOverride {
	return func(input *session.Input) {
		exclude := make([]int, 0, len(wrappers))
		for _, wrapper := range wrappers {
			exclude = append(exclude, wrapper.LocalPort())
		}

		input.Port = strconv.Itoa(RandPortExclude(exclude))
	}
}

func Session(wrapper *TestContainerWrapper, overrides ...SessionOverride) *session.Session {
	container := wrapper.Container
	sett := container.ContainerSettings()

	input := session.Input{
		AvailableHosts: []session.Host{
			{Host: "127.0.0.1", Name: "localhost"},
		},
		User:       sett.Username,
		Port:       container.LocalPortString(),
		BecomePass: sett.Password,
	}

	for _, override := range overrides {
		override(&input)
	}

	return session.NewSession(input)
}

func SessionWithBastion(wrapper *TestContainerWrapper, bastionWrapper *TestContainerWrapper, overrides ...SessionOverride) *session.Session {
	container := wrapper.Container
	sett := container.ContainerSettings()

	bastionContainer := bastionWrapper.Container
	bastionSetting := bastionContainer.ContainerSettings()

	input := session.Input{
		AvailableHosts: []session.Host{
			{Host: "127.0.0.1", Name: "localhost"},
		},
		User:            sett.Username,
		Port:            container.RemotePortString(),
		BecomePass:      sett.Password,
		BastionHost:     "127.0.0.1",
		BastionPort:     bastionContainer.LocalPortString(),
		BastionUser:     bastionSetting.Username,
		BastionPassword: bastionSetting.Password,
	}

	for _, override := range overrides {
		override(&input)
	}

	return session.NewSession(input)
}

func FakeSession() *session.Session {
	host := IncorrectHost()
	return session.NewSession(session.Input{
		AvailableHosts: []session.Host{{Host: host, Name: host}},
		User:           "user",
		Port:           strconv.Itoa(RandPort()),
		BecomePass:     RandPassword(6),
	})
}
