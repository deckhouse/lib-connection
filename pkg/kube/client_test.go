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

package kube

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFakeClient(t *testing.T) {
	t.Run("InitContext does not panics and no rewrite client", func(t *testing.T) {
		client := NewFakeKubernetesClient()
		innerClient := client.KubeClient

		doInit := func() {
			err := client.InitContext(context.TODO(), &Config{})
			require.NoError(t, err, "init context should not fail")
		}
		require.NotPanics(t, doInit, "init context should not panic")
		require.True(t, client.KubeClient == innerClient, "should not rewrite client")
	})
}
