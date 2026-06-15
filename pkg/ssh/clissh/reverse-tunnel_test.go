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

package clissh

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
)

// failingChecker always reports the tunnel as broken, keeping the health
// monitor busy in its check/restart cycle (outside the select that receives
// the stop signal) — the window in which the Stop deadlock was observed.
type failingChecker struct{}

func (failingChecker) CheckTunnel(context.Context) (string, error) {
	return "", errors.New("tunnel check failed")
}

type noopKiller struct{}

func (noopKiller) KillTunnel(context.Context) (string, error) {
	return "", nil
}

func newTestTunnel(t *testing.T) *ReverseTunnel {
	t.Helper()

	sett := settings.NewBaseProviders(settings.ProviderParams{
		TmpDir: t.TempDir(),
	})
	// Port 1 on localhost: ssh exits almost immediately, so the tunnel
	// process dies and the cmd.Wait goroutine fires errorCh — same as a
	// dropped ssh connection during teardown.
	sess := session.NewSession(session.Input{
		User: "nobody",
		Port: "1",
		AvailableHosts: []session.Host{
			{Host: "127.0.0.1"},
		},
	})

	return NewReverseTunnel(sett, sess, "127.0.0.1:0:127.0.0.1:0")
}

// TestReverseTunnelStopDoesNotDeadlock reproduces the bootstrap-teardown hang:
// Stop() held tunMutex while blocking on an unbuffered stopCh send, and the
// health monitor — busy handling an errorCh event — blocked on the same mutex
// in isStarted(), so neither side could proceed (observed live via dlv:
// goroutine in stop() at "chan send", goroutine in isStarted() at "Mutex.Lock").
func TestReverseTunnelStopDoesNotDeadlock(t *testing.T) {
	// The deadlock is a race: the monitor must be outside its select when
	// Stop fires. Several iterations make the window reliably hit.
	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithCancel(context.Background())

		tun := newTestTunnel(t)
		if err := tun.Up(); err != nil {
			cancel()
			t.Skipf("cannot start ssh process: %v", err)
		}

		tun.StartHealthMonitor(ctx, failingChecker{}, noopKiller{})

		// Give the dying ssh process time to fire errorCh and the monitor
		// time to leave its select (it is busy in checkReverseTunnel /
		// restart handling thanks to the failing checker).
		time.Sleep(300 * time.Millisecond)

		done := make(chan struct{})
		go func() {
			tun.Stop()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("iteration %d: Stop() deadlocked", i)
		}
		cancel()
	}
}

// TestReverseTunnelDoubleStop ensures a second Stop (teardown paths can run
// twice) returns immediately instead of blocking on an already-stopped monitor.
func TestReverseTunnelDoubleStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tun := newTestTunnel(t)
	if err := tun.Up(); err != nil {
		t.Skipf("cannot start ssh process: %v", err)
	}
	tun.StartHealthMonitor(ctx, failingChecker{}, noopKiller{})

	for i := 0; i < 2; i++ {
		done := make(chan struct{})
		go func() {
			tun.Stop()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("Stop() call %d deadlocked", i+1)
		}
	}
}
