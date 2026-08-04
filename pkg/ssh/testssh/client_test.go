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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/deckhouse/lib-connection/pkg/ssh/session"
	"github.com/deckhouse/lib-connection/pkg/tests"
)

func TestProviderStandaloneClientFor(t *testing.T) {
	tests.ShouldNewTest(t, "TestProviderStandaloneClientFor", tests.TestIsIntegration(false))

	sessionForHost := func(host string) *session.Session {
		return session.NewSession(session.Input{
			User: "user",
			Port: "22",
			AvailableHosts: []session.Host{
				{
					Host: host,
					Name: host,
				},
			},
		})
	}

	t.Run("reuse cached live client", func(t *testing.T) {
		provider := NewSSHProvider(sessionForHost("192.168.0.1"), true)
		ctx := t.Context()
		sess := sessionForHost("192.168.0.2")

		client, err := provider.StandaloneClientFor(ctx, "node-1", sess, nil)
		require.NoError(t, err, "should create client")
		require.True(t, client.Live(), "client should be live")

		cachedClient, err := provider.StandaloneClientFor(ctx, "node-1", sess, nil)
		require.NoError(t, err, "should provide client")
		require.True(t, client == cachedClient, "should reuse cached client")

		anotherClient, err := provider.StandaloneClientFor(ctx, "node-2", sessionForHost("192.168.0.3"), nil)
		require.NoError(t, err, "should create client")
		require.False(t, client == anotherClient, "should create another client for another key")
		require.Len(t, provider.keyedClients, 2, "should cache client for every key")
	})

	t.Run("cleanup stops keyed clients", func(t *testing.T) {
		provider := NewSSHProvider(sessionForHost("192.168.0.1"), true)
		ctx := t.Context()
		sess := sessionForHost("192.168.0.2")

		client, err := provider.StandaloneClientFor(ctx, "node-1", sess, nil)
		require.NoError(t, err, "should create client")

		require.NoError(t, provider.Cleanup(ctx), "should cleanup")
		require.True(t, client.IsStopped(), "should stop keyed client")
		require.Empty(t, provider.keyedClients, "should drop all keyed clients")

		clientAfterCleanup, err := provider.StandaloneClientFor(ctx, "node-1", sess, nil)
		require.NoError(t, err, "should create client after cleanup")
		require.False(t, client == clientAfterCleanup, "should create new client after cleanup")
	})

	t.Run("nil session returns error", func(t *testing.T) {
		provider := NewSSHProvider(sessionForHost("192.168.0.1"), true)

		client, err := provider.StandaloneClientFor(t.Context(), "node-1", nil, nil)
		require.Error(t, err, "should reject nil session")
		require.Nil(t, client, "client should not be provided")
	})

	t.Run("replace dead client", func(t *testing.T) {
		provider := NewSSHProvider(sessionForHost("192.168.0.1"), true)
		ctx := t.Context()
		sess := sessionForHost("192.168.0.2")

		client, err := provider.StandaloneClientFor(ctx, "node-1", sess, nil)
		require.NoError(t, err, "should create client")

		client.Stop()
		require.False(t, client.Live(), "stopped client should not be live")

		newClient, err := provider.StandaloneClientFor(ctx, "node-1", sess, nil)
		require.NoError(t, err, "should create new client")
		require.False(t, client == newClient, "should replace dead client")
		require.True(t, newClient.Live(), "new client should be live")
		require.Len(t, provider.keyedClients, 1, "should keep one client per key")
	})
}
