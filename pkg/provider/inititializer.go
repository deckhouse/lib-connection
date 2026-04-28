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

	"github.com/name212/govalue"
	"k8s.io/apimachinery/pkg/runtime/schema"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/kube"
)

var (
	_ SSHProviderInitializer            = &SimpleSSHProviderInitializer{}
	_ SSHProviderInitializerWithCleanup = &SimpleSSHProviderInitializer{}

	_ SSHProviderInitializer            = &ErrorSSHProviderInitializer{}
	_ SSHProviderInitializerWithCleanup = &ErrorSSHProviderInitializer{}

	_ SSHProviderInitializer            = &ProvideErrorSSHProviderInitializer{}
	_ SSHProviderInitializerWithCleanup = &ProvideErrorSSHProviderInitializer{}

	_ KubeProviderInitializer            = &SimpleKubeProviderInitializer{}
	_ KubeProviderInitializerWithCleanup = &SimpleKubeProviderInitializer{}

	_ KubeProviderInitializer            = &FakeKubeProviderInitializer{}
	_ KubeProviderInitializerWithCleanup = &FakeKubeProviderInitializer{}
)

var (
	ErrCannotProvideSSHProvider = errors.New("cannot provide ssh provider initializer")
)

type SSHProviderInitializer interface {
	GetSSHProvider(ctx context.Context) (connection.SSHProvider, error)
}

type SSHProviderInitializerWithCleanup interface {
	SSHProviderInitializer
	Cleanup(ctx context.Context) error
}

type KubeProviderInitializer interface {
	GetKubeProvider(ctx context.Context) (connection.KubeProvider, error)
}

type KubeProviderInitializerWithCleanup interface {
	KubeProviderInitializer
	Cleanup(ctx context.Context) error
}

type SimpleSSHProviderInitializer struct {
	provider connection.SSHProvider
}

func NewSimpleSSHProviderInitializer(provider connection.SSHProvider) *SimpleSSHProviderInitializer {
	return &SimpleSSHProviderInitializer{
		provider: provider,
	}
}

func (i *SimpleSSHProviderInitializer) GetSSHProvider(_ context.Context) (connection.SSHProvider, error) {
	return i.provider, nil
}

func (i *SimpleSSHProviderInitializer) Cleanup(ctx context.Context) error {
	if govalue.Nil(i.provider) {
		return nil
	}

	return i.provider.Cleanup(ctx)
}

// ErrorSSHProviderInitializer
// provide ErrorSSHProvider
// this provider returns error for every
// SSHProvider methods call
type ErrorSSHProviderInitializer struct {
	*SimpleSSHProviderInitializer
}

func NewErrorSSHProviderInitializer(err error) *ErrorSSHProviderInitializer {
	return &ErrorSSHProviderInitializer{
		SimpleSSHProviderInitializer: NewSimpleSSHProviderInitializer(
			NewErrorSSHProvider(err),
		),
	}
}

// ProvideErrorSSHProviderInitializer
// this provider returns error for every GetSSHProvider call
// for fail fast in GetRunnerInterface func
type ProvideErrorSSHProviderInitializer struct {
	err error
}

func NewProvideErrorSSHProviderInitializer(err error) *ProvideErrorSSHProviderInitializer {
	if err == nil {
		err = errors.New("unknown error")
	}

	return &ProvideErrorSSHProviderInitializer{
		err: err,
	}
}

func (i *ProvideErrorSSHProviderInitializer) GetSSHProvider(_ context.Context) (connection.SSHProvider, error) {
	return nil, fmt.Errorf("%w: %w", ErrCannotProvideSSHProvider, i.err)
}

func (i *ProvideErrorSSHProviderInitializer) Cleanup(_ context.Context) error {
	return nil
}

type SimpleKubeProviderInitializer struct {
	provider connection.KubeProvider
}

func NewSimpleKubeProviderInitializer(provider connection.KubeProvider) *SimpleKubeProviderInitializer {
	return &SimpleKubeProviderInitializer{
		provider: provider,
	}
}

func (i *SimpleKubeProviderInitializer) GetKubeProvider(_ context.Context) (connection.KubeProvider, error) {
	return i.provider, nil
}

func (i *SimpleKubeProviderInitializer) Cleanup(ctx context.Context) error {
	if govalue.Nil(i.provider) {
		return nil
	}

	return i.provider.Cleanup(ctx)
}

type FakeKubeProviderInitializer struct {
	*SimpleKubeProviderInitializer
}

func NewFakeKubeProviderInitializer(gvrs ...map[schema.GroupVersionResource]string) *FakeKubeProviderInitializer {
	return &FakeKubeProviderInitializer{
		SimpleKubeProviderInitializer: NewSimpleKubeProviderInitializer(
			NewFakeKubeProvider(gvrs...),
		),
	}
}

func NewFakeKubeProviderInitializerWithPodExec(podExecutor kube.PodCommandExecutor, gvrs ...map[schema.GroupVersionResource]string) *FakeKubeProviderInitializer {
	return &FakeKubeProviderInitializer{
		SimpleKubeProviderInitializer: NewSimpleKubeProviderInitializer(
			NewFakeKubeProviderWithExec(podExecutor, gvrs...),
		),
	}
}
