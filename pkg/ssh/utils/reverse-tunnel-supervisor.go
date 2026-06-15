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
	"sync"

	"github.com/deckhouse/lib-dhctl/pkg/log"

	connection "github.com/deckhouse/lib-connection/pkg"
)

// MaxConsecutiveTunnelRestarts guards against a tunnel that can never come
// back up: better to crash loudly than to spin forever.
const MaxConsecutiveTunnelRestarts = 1024

// TunnelBackend is the transport-specific part of a reverse tunnel: how to
// bring one instance up, how to tear it down, and how its termination is
// observed.
type TunnelBackend interface {
	// StartTunnel brings a tunnel instance up. Implementations must refuse to
	// start (return an error) once ctx is canceled — this is what guarantees
	// nothing is brought up behind a Stop.
	StartTunnel(ctx context.Context) error

	// StopTunnel tears the current tunnel instance down. Must be idempotent
	// and must not block on the supervisor making progress.
	StopTunnel()

	// TunnelDone returns the termination channel of the current instance, or
	// nil when nothing is up. The channel reports the instance's exit at most
	// once and must never block the sender (i.e. it is buffered); it stays
	// valid after the instance dies.
	TunnelDone() <-chan error

	// CheckTunnel probes the tunnel end-to-end, honoring ctx. True = healthy.
	// Retry policy lives in the implementation; it also paces the supervision
	// loop, so a CheckTunnel that fails instantly produces a hot restart loop —
	// keep at least one retry/wait inside.
	CheckTunnel(ctx context.Context) bool
}

// TunnelSupervisor keeps a reverse tunnel alive: it is the only actor that
// restarts tunnel instances, and its whole lifecycle is driven by context
// cancellation, which never blocks.
//
// This replaces a previous per-implementation monitor that signaled stop over
// an unbuffered channel while holding the tunnel mutex — the monitor could
// simultaneously need that mutex to make progress, deadlocking the caller's
// teardown (observed live as a dhctl bootstrap hang in tomb.WaitShutdown).
type TunnelSupervisor struct {
	backend TunnelBackend
	killer  connection.ReverseTunnelKiller
	logger  log.Logger

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func NewTunnelSupervisor(backend TunnelBackend, killer connection.ReverseTunnelKiller, logger log.Logger) *TunnelSupervisor {
	return &TunnelSupervisor{
		backend: backend,
		killer:  killer,
		logger:  logger,
	}
}

// Start launches the supervision loop. A previous loop, if any, is fully
// stopped first, so at most one loop ever supervises the backend.
func (s *TunnelSupervisor) Start(ctx context.Context) {
	s.Stop()

	loopCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	s.mu.Lock()
	s.cancel = cancel
	s.done = done
	s.mu.Unlock()

	go s.run(loopCtx, done)
}

// Stop cancels the supervision loop and waits until it has fully unwound.
// The lock is NOT held across the wait: cancellation is the only signal, and
// the loop itself never takes this lock. Stop does not touch the tunnel —
// that is the owner's job (backend.StopTunnel after Stop returns).
func (s *TunnelSupervisor) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	done := s.done
	s.cancel = nil
	s.done = nil
	s.mu.Unlock()

	if cancel == nil {
		return
	}

	cancel()
	<-done
}

func (s *TunnelSupervisor) run(ctx context.Context, done chan<- struct{}) {
	s.logger.DebugF("Start health monitor")
	defer func() {
		s.logger.DebugF("Stop health monitor")
		close(done)
	}()

	restarts := 0

	// Trade-off: there is no periodic active probing in the steady state —
	// once CheckTunnel passes, the loop sleeps on TunnelDone.
	//
	// We accept this: the tunnel's TCP keepalive is considered sufficient
	// proof from our side that the reverse tunnel is alive,
	// and we trust the cli/go ssh implementations to report
	// an error (firing TunnelDone) when keepalive fails.
	//
	// The gap we knowingly accept is a silent degradation with the ssh
	// session still alive (e.g., the remote listener is gone) — that would
	// require active probing to detect.
	for {
		if ctx.Err() != nil {
			return
		}

		if !s.backend.CheckTunnel(ctx) {
			if ctx.Err() != nil {
				// A check that failed because the context died during shutdown
				// is not a tunnel failure; don't restart what Stop is killing.
				return
			}

			// Only restarts that never succeed count toward the panic guard —
			// a successful restart proves the tunnel can come back (matches
			// the historical monitor, which reset its counter there too).
			if s.restartTunnel(ctx) {
				restarts = 0
			} else {
				restarts++
				if restarts > MaxConsecutiveTunnelRestarts {
					panic("Reverse tunnel restarts count exceeds 1024")
				}
			}
			continue
		}

		restarts = 0

		// Healthy: sleep until the tunnel dies or we are stopped. A nil
		// TunnelDone (nothing is up) blocks forever, leaving ctx as the only
		// wake-up; the post-cancellation iteration exits the loop.
		select {
		case <-ctx.Done():
			return
		case err := <-s.backend.TunnelDone():
			s.logger.DebugF("Tunnel was stopped with error '%v'. Try restart fully\n", err)
		}
	}
}

// restartTunnel tears the current tunnel down, clears the remote side and
// brings a fresh instance up. Returns whether the new instance came up; the
// loop re-checks and retries on the next iteration either way.
func (s *TunnelSupervisor) restartTunnel(ctx context.Context) bool {
	s.backend.StopTunnel()

	s.logger.DebugF("Kill remote tunnel listener\n")
	if out, err := s.killer.KillTunnel(ctx); err != nil {
		s.logger.DebugF("Kill tunnel was finished with error: %v; stdout: '%s'\n", err, out)
		return false
	}

	if err := s.backend.StartTunnel(ctx); err != nil {
		s.logger.DebugF("Restart failed with error: %v\n", err)
		return false
	}

	s.logger.DebugF("Restart successful\n")
	return true
}
