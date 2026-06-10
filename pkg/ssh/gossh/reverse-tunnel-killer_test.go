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

package gossh

import (
	"context"
	"testing"

	"github.com/deckhouse/lib-connection/pkg/ssh/utils"
)

type markerKiller struct{}

func (markerKiller) KillTunnel(context.Context) (string, error) { return "", nil }

// The health monitor must use the caller's killer: after a half-open ssh
// break only the kill script (run over a fresh session) can free the remote
// port held by the zombie sshd session. gossh used to silently replace the
// provided killer with EmptyReverseTunnelKiller, making recovery from such
// breaks impossible ("address already in use" on every re-listen).
func TestEffectiveKillerKeepsProvidedKiller(t *testing.T) {
	k := markerKiller{}
	if got := defaultKiller(k); got != k {
		t.Fatalf("provided killer was replaced: got %T", got)
	}
}

func TestEffectiveKillerDefaultsToEmpty(t *testing.T) {
	got := defaultKiller(nil)
	if _, ok := got.(utils.EmptyReverseTunnelKiller); !ok {
		t.Fatalf("nil killer must default to EmptyReverseTunnelKiller, got %T", got)
	}
}
