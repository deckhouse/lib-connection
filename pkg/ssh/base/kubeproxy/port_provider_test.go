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

package kubeproxy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPortProvider(t *testing.T) {
	t.Run("Use non default", func(t *testing.T) {
		const usedPort = 22222
		provider := NewPortProvider(usedPort)

		for i := 0; i < 5; i++ {
			got := provider.Next()
			require.Equal(t, usedPort, got, "should always return the same port")
			require.Len(t, provider.used, 0, "not save same port in used")
		}
	})

	t.Run("Use default", func(t *testing.T) {
		provider := NewPortProvider(-1)

		// first call return default port
		got := provider.Next()
		require.Equal(t, DefaultLocalAPIPort, got, "should return default")

		// next calls return random
		for i := 1; i < 5; i++ {
			got := provider.Next()

			require.NotEqual(t, DefaultLocalAPIPort, got, "should not default port")

			require.True(t, got >= 22340, "should port in range")
			require.True(t, got <= 22499, "should port in range")

			require.Len(t, provider.used, i+1, "used ports should expected len")
			require.Contains(t, provider.used, got, "used ports should add new port")
		}
	})
}
