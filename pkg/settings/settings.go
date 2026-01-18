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

package settings

import (
	"os"

	"github.com/deckhouse/lib-dhctl/pkg/log"
)

var (
	defaultLogger      log.Logger = log.NewSilentLogger()
	defaultNodeBinPath string     = "/opt/deckhouse/bin"
	defaultNodeTmpPath            = "/opt/deckhouse/tmp"
	defaultTmpDir                 = os.TempDir() + "/dhctl"
	defaultOnShutdown  OnShutdown = func(string, func()) {}
)

type OnShutdown func(name string, action func())

type Settings interface {
	Logger() log.Logger
	LoggerProvider() log.LoggerProvider
	NodeTmpDir() string
	NodeBinPath() string
	IsDebug() bool
	TmpDir() string
	AuthSock() string
	RegisterOnShutdown(string, func())
}

type ProviderParams struct {
	LoggerProvider log.LoggerProvider
	IsDebug        bool
	NodeTmpPath    string
	NodeBinPath    string
	TmpDir         string
	AuthSock       string
	OnShutdown     OnShutdown
}

type BaseProviders struct {
	params ProviderParams

	onShutdown OnShutdown
}

func NewBaseProviders(params ProviderParams) *BaseProviders {
	onShutdown := defaultOnShutdown
	if params.OnShutdown != nil {
		onShutdown = params.OnShutdown
	}

	return &BaseProviders{
		params:     params,
		onShutdown: onShutdown,
	}
}

func (b *BaseProviders) Logger() log.Logger {
	return log.ProvideSafe(b.params.LoggerProvider, defaultLogger)
}

func (b *BaseProviders) WithLogger(provider log.LoggerProvider) *BaseProviders {
	b.params.LoggerProvider = provider
	return b
}

func (b *BaseProviders) LoggerProvider() log.LoggerProvider {
	return b.params.LoggerProvider
}

func (b *BaseProviders) NodeTmpDir() string {
	if b.params.NodeTmpPath != "" {
		return b.params.NodeTmpPath
	}
	return defaultNodeTmpPath
}

func (b *BaseProviders) NodeBinPath() string {
	if b.params.NodeBinPath != "" {
		return b.params.NodeBinPath
	}

	return defaultNodeBinPath
}

func (b *BaseProviders) TmpDir() string {
	if b.params.TmpDir != "" {
		return b.params.TmpDir
	}
	return defaultTmpDir
}

func (b *BaseProviders) IsDebug() bool {
	return b.params.IsDebug
}

func (b *BaseProviders) AuthSock() string {
	if b.params.AuthSock != "" {
		return b.params.AuthSock
	}

	return os.Getenv("SSH_AUTH_SOCK")
}

func (b *BaseProviders) RegisterOnShutdown(name string, action func()) {
	b.onShutdown(name, action)
}

// SetDefaultLogger
// Deprecated:
// for backward compatibility please pass logger to all structure directly
func SetDefaultLogger(logger log.Logger) {
	defaultLogger = logger
}

func SetNodeTmpPath(path string) {
	defaultNodeTmpPath = path
}
