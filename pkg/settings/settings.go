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
	"context"
	"log/slog"
	"os"

	"github.com/deckhouse/lib-dhctl/pkg/logger"
	"github.com/name212/govalue"
)

var (
	defaultLogger      *slog.Logger = logger.FromContext(context.Background())
	defaultNodeBinPath string       = "/opt/deckhouse/bin"
	defaultNodeTmpPath              = "/opt/deckhouse/tmp"
	defaultTmpDir                   = os.TempDir() + "/dhctl"
	defaultOnShutdown  OnShutdown   = func(string, func()) {}
)

type OnShutdown func(name string, action func())

type Settings interface {
	Logger() *slog.Logger
	NodeTmpDir() string
	NodeBinPath() string
	IsDebug() bool
	TmpDir() string
	AuthSock() string
	EnvsPrefix() string
	RegisterOnShutdown(string, func())
}

type ProviderParams struct {
	Logger      *slog.Logger
	IsDebug     bool
	NodeTmpPath string
	NodeBinPath string
	TmpDir      string
	AuthSock    string
	EnvsPrefix  string
	OnShutdown  OnShutdown
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

func (b *BaseProviders) Logger() *slog.Logger {
	if govalue.NotNil(b.params.Logger) {
		return b.params.Logger
	}

	return defaultLogger
}

func (b *BaseProviders) WithLogger(l *slog.Logger) *BaseProviders {
	b.params.Logger = l
	return b
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

	return os.Getenv(SSHAgentAuthSockEnv)
}

func (b *BaseProviders) EnvsPrefix() string {
	return b.params.EnvsPrefix
}

func (b *BaseProviders) RegisterOnShutdown(name string, action func()) {
	b.onShutdown(name, action)
}

type CloneOpt func(*BaseProviders)

func CloneWithEnvsPrefix(prefix string) CloneOpt {
	return func(p *BaseProviders) {
		p.params.EnvsPrefix = prefix
	}
}

func CloneWithAuthSock(path string) CloneOpt {
	return func(p *BaseProviders) {
		p.params.AuthSock = path
	}
}

func CloneWithLogger(l *slog.Logger) CloneOpt {
	return func(p *BaseProviders) {
		p.params.Logger = l
	}
}

func CloneWithTmpDir(dir string) CloneOpt {
	return func(p *BaseProviders) {
		p.params.TmpDir = dir
	}
}

func CloneWithNodeTmpPath(dir string) CloneOpt {
	return func(p *BaseProviders) {
		p.params.NodeTmpPath = dir
	}
}

func (b *BaseProviders) Clone(opts ...CloneOpt) *BaseProviders {
	clone := *b

	for _, opt := range opts {
		opt(&clone)
	}

	return &clone
}
