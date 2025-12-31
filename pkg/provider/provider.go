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

	"github.com/hashicorp/go-multierror"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/settings"
	sshconfig "github.com/deckhouse/lib-connection/pkg/ssh/config"
)

type DefaultProvider struct {
	sshProvider connection.SSHProvider
}

func NewDefaultProvider(sett settings.Settings, sshConnectionConfig *sshconfig.ConnectionConfig) *DefaultProvider {
	return &DefaultProvider{
		sshProvider: NewDefaultSSHProvider(sett, sshConnectionConfig),
	}
}

func (p *DefaultProvider) SSHProvider() connection.SSHProvider {
	return p.sshProvider
}

func (p *DefaultProvider) Cleanup(ctx context.Context) error {
	var errs *multierror.Error

	if err := p.sshProvider.Cleanup(ctx); err != nil {
		errs = multierror.Append(errs, err)
	}

	return errs.ErrorOrNil()
}
