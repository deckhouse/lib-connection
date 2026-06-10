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

package utils

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/log"
)

// fakeBackend simulates a tunnel whose health check can be made to block —
// reproducing the moment the old per-implementation monitor was busy outside
// its select while a teardown signaled it, which deadlocked dhctl bootstrap.
type fakeBackend struct {
	mu        sync.Mutex
	done      chan error
	healthy   atomic.Bool
	checkGate chan struct{} // non-nil: CheckTunnel blocks until closed (or ctx)

	starts atomic.Int64
	stops  atomic.Int64
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{done: make(chan error, 1)}
}

func (b *fakeBackend) StartTunnel(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.starts.Add(1)
	b.mu.Lock()
	b.done = make(chan error, 1)
	b.mu.Unlock()
	return nil
}

func (b *fakeBackend) StopTunnel() {
	b.stops.Add(1)
}

func (b *fakeBackend) TunnelDone() <-chan error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.done
}

func (b *fakeBackend) CheckTunnel(ctx context.Context) bool {
	if gate := b.checkGate; gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return false
		}
	}
	// Real checkers pace the loop with retry waits; emulate that, otherwise
	// an always-failing check spins the restart loop hot.
	time.Sleep(time.Millisecond)
	return b.healthy.Load()
}

func (b *fakeBackend) dieWith(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.done <- err
}

type fakeKiller struct{ kills atomic.Int64 }

func (k *fakeKiller) KillTunnel(context.Context) (string, error) {
	k.kills.Add(1)
	return "", nil
}

func stopWithin(t *testing.T, s *TunnelSupervisor, d time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		s.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatal("supervisor Stop() did not return: deadlock")
	}
}

// Stop must return promptly even when the loop is parked inside a long health
// check — the situation that deadlocked the old monitor.
func TestSupervisorStopDuringBlockedCheck(t *testing.T) {
	b := newFakeBackend()
	b.checkGate = make(chan struct{}) // never closed: check blocks until ctx

	s := NewTunnelSupervisor(b, &fakeKiller{}, log.NewSilentLogger())
	s.Start(context.Background())

	time.Sleep(50 * time.Millisecond) // loop is now inside CheckTunnel
	stopWithin(t, s, 5*time.Second)
}

// Stop must return promptly while the loop is busy with restart churn.
func TestSupervisorStopDuringRestartChurn(t *testing.T) {
	b := newFakeBackend()
	b.healthy.Store(false) // every check fails -> restart loop

	s := NewTunnelSupervisor(b, &fakeKiller{}, log.NewSilentLogger())
	s.Start(context.Background())

	time.Sleep(100 * time.Millisecond)
	stopWithin(t, s, 5*time.Second)

	if b.starts.Load() == 0 {
		t.Fatal("expected at least one restart attempt")
	}
}

// A tunnel death while healthy must wake the loop and trigger a restart.
func TestSupervisorRestartsDeadTunnel(t *testing.T) {
	b := newFakeBackend()
	b.healthy.Store(true)
	k := &fakeKiller{}

	s := NewTunnelSupervisor(b, k, log.NewSilentLogger())
	s.Start(context.Background())
	defer stopWithin(t, s, 5*time.Second)

	time.Sleep(50 * time.Millisecond) // loop checked healthy, parked on TunnelDone
	// The death event wakes the loop; the now-failing check triggers the restart.
	b.healthy.Store(false)
	b.dieWith(errors.New("connection reset"))

	deadline := time.After(5 * time.Second)
	for b.starts.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("supervisor did not restart a dead tunnel")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// After Stop, no restart may resurrect the tunnel (the old monitor could
// receive a queued restart signal and bring ssh back up post-teardown).
func TestSupervisorNoResurrectionAfterStop(t *testing.T) {
	b := newFakeBackend()
	b.healthy.Store(false)

	s := NewTunnelSupervisor(b, &fakeKiller{}, log.NewSilentLogger())
	s.Start(context.Background())
	time.Sleep(100 * time.Millisecond)
	stopWithin(t, s, 5*time.Second)

	startsAtStop := b.starts.Load()
	time.Sleep(200 * time.Millisecond)
	if got := b.starts.Load(); got != startsAtStop {
		t.Fatalf("tunnel resurrected after Stop: starts %d -> %d", startsAtStop, got)
	}
}

// Double Stop and Stop-without-Start must be safe no-ops.
func TestSupervisorStopIdempotent(t *testing.T) {
	b := newFakeBackend()
	b.healthy.Store(true)

	s := NewTunnelSupervisor(b, &fakeKiller{}, log.NewSilentLogger())
	stopWithin(t, s, time.Second) // never started

	s.Start(context.Background())
	time.Sleep(50 * time.Millisecond)
	stopWithin(t, s, 5*time.Second)
	stopWithin(t, s, time.Second) // second stop
}

// Restarting the supervisor (Start after Start) must not leak the old loop.
func TestSupervisorRestartReplacesLoop(t *testing.T) {
	b := newFakeBackend()
	b.healthy.Store(true)

	s := NewTunnelSupervisor(b, &fakeKiller{}, log.NewSilentLogger())
	s.Start(context.Background())
	s.Start(context.Background()) // replaces the first loop
	stopWithin(t, s, 5*time.Second)
}

// recorder collects ordered events from the backend and the killer so tests
// can assert cross-object sequencing (kill must precede a successful start).
type recorder struct {
	mu     sync.Mutex
	events []string
}

func (r *recorder) add(e string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recorder) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

// zombiePortBackend simulates the half-open ssh break: the remote port is
// still held by a dead sshd session ("zombie"), so StartTunnel fails with
// address-already-in-use until something actually frees the port. Closing the
// local listener (StopTunnel) does NOT free it — exactly the gossh situation
// where cancel-tcpip-forward never reaches sshd over a dead transport.
type zombiePortBackend struct {
	rec *recorder

	mu       sync.Mutex
	portHeld bool
	up       bool
	done     chan error

	starts     atomic.Int64
	startFails atomic.Int64
}

func newZombiePortBackend(rec *recorder) *zombiePortBackend {
	return &zombiePortBackend{rec: rec, portHeld: true}
}

func (b *zombiePortBackend) StartTunnel(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.portHeld {
		b.startFails.Add(1)
		b.rec.add("start-fail")
		return errors.New("failed to listen remote: address already in use")
	}

	b.up = true
	b.done = make(chan error, 1)
	b.starts.Add(1)
	b.rec.add("start-ok")
	return nil
}

func (b *zombiePortBackend) StopTunnel() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.up = false
	b.rec.add("stop")
}

func (b *zombiePortBackend) TunnelDone() <-chan error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.up {
		return nil
	}
	return b.done
}

func (b *zombiePortBackend) CheckTunnel(ctx context.Context) bool {
	select { // pace the loop like real checkers' retry waits do
	case <-time.After(time.Millisecond):
	case <-ctx.Done():
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.up
}

// freeingKiller is the working kill script: it frees the zombie-held port.
type freeingKiller struct {
	backend *zombiePortBackend
	rec     *recorder
	kills   atomic.Int64
}

func (k *freeingKiller) KillTunnel(context.Context) (string, error) {
	k.backend.mu.Lock()
	k.backend.portHeld = false
	k.backend.mu.Unlock()
	k.kills.Add(1)
	k.rec.add("kill")
	return "", nil
}

// uselessKiller succeeds but frees nothing — behaviorally identical to
// EmptyReverseTunnelKiller against a zombie sshd session.
type uselessKiller struct{}

func (uselessKiller) KillTunnel(context.Context) (string, error) { return "", nil }

// After a half-open break the supervisor must free the zombie-held remote
// port via the killer BEFORE re-binding — otherwise the re-listen can never
// succeed. Asserts both recovery and the kill→start ordering.
func TestSupervisorFreesZombiePortViaKiller(t *testing.T) {
	rec := &recorder{}
	b := newZombiePortBackend(rec)
	k := &freeingKiller{backend: b, rec: rec}

	s := NewTunnelSupervisor(b, k, log.NewSilentLogger())
	s.Start(context.Background())
	defer stopWithin(t, s, 5*time.Second)

	deadline := time.After(5 * time.Second)
	for b.starts.Load() == 0 {
		select {
		case <-deadline:
			t.Fatalf("tunnel never recovered from zombie-held port; events: %v", rec.list())
		case <-time.After(5 * time.Millisecond):
		}
	}

	if k.kills.Load() == 0 {
		t.Fatal("killer was never invoked")
	}

	// The first successful start must come after at least one kill.
	killSeen := false
	for _, e := range rec.list() {
		if e == "kill" {
			killSeen = true
		}
		if e == "start-ok" {
			if !killSeen {
				t.Fatalf("tunnel restarted before the killer freed the port; events: %v", rec.list())
			}
			break
		}
	}
}

// Documents the regression this guards against: with a killer that cannot
// free the port (gossh used to silently swap the caller's killer for an empty
// one), the zombie-held port makes recovery impossible — every re-listen
// fails — while teardown must still work.
func TestSupervisorZombiePortStuckWithUselessKiller(t *testing.T) {
	rec := &recorder{}
	b := newZombiePortBackend(rec)

	s := NewTunnelSupervisor(b, uselessKiller{}, log.NewSilentLogger())
	s.Start(context.Background())

	time.Sleep(150 * time.Millisecond)

	if got := b.starts.Load(); got != 0 {
		t.Fatalf("tunnel recovered without the port being freed: %d starts", got)
	}
	if b.startFails.Load() == 0 {
		t.Fatal("expected re-listen attempts against the held port")
	}

	stopWithin(t, s, 5*time.Second)
}
