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

package tests

import (
	"context"
	"strconv"

	dhlog "github.com/deckhouse/lib-dhctl/pkg/logger"

	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
)

// func TestLogger(opts ...TestOpt) *log.InMemoryLogger {
// 	options := applyTestOpts(opts...)

// 	loggerOptions := log.LoggerOptions{IsDebug: options.isDebug}
// 	if options.logBuffer != nil {
// 		loggerOptions.OutStream = options.logBuffer
// 	}

// 	res := log.NewInMemoryLoggerWithParent(log.NewPrettyLogger(loggerOptions))
// 	if options.noLogDebug {
// 		res.WithNoDebug(true)
// 	}

// 	return res
// }

func getDefaultParams(_ *Test) settings.ProviderParams {
	return settings.ProviderParams{
		Logger:  dhlog.FromContext(context.Background()),
		IsDebug: true,
	}
}

func CreateDefaultTestSettings(test *Test) settings.Settings {
	return settings.NewBaseProviders(getDefaultParams(test))
}

func getParamsNoDebug(_ *Test) settings.ProviderParams {
	return settings.ProviderParams{
		Logger:  dhlog.FromContext(context.Background()),
		IsDebug: false,
	}
}

func CreateTestSettingNoDebug(test *Test) settings.Settings {
	return settings.NewBaseProviders(getParamsNoDebug(test))
}

func CreateDefaultTestSettingsWithAgent(test *Test, agentSockPath string) settings.Settings {
	params := getDefaultParams(test)
	params.AuthSock = agentSockPath
	return settings.NewBaseProviders(params)
}

type SessionOverride func(input *session.Input)

func generateIncorrectPort(wrappers ...*TestContainerWrapper) string {
	exclude := make([]int, 0, len(wrappers))
	for _, wrapper := range wrappers {
		exclude = append(exclude, wrapper.LocalPort())
	}

	return strconv.Itoa(RandPortExclude(exclude))
}

func OverrideSessionWithIncorrectPort(wrappers ...*TestContainerWrapper) SessionOverride {
	return func(input *session.Input) {
		input.Port = generateIncorrectPort(wrappers...)
	}
}

func OverrideSessionWithIncorrectBastionPort(wrappers ...*TestContainerWrapper) SessionOverride {
	return func(input *session.Input) {
		input.BastionPort = generateIncorrectPort(wrappers...)
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
			{Host: container.GetContainerIP(), Name: container.GetContainerIP()},
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
