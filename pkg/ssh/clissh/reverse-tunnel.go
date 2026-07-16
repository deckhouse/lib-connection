// Copyright 2024 Flant JSC
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
	"fmt"
	"math/rand/v2"
	"os/exec"
	"sync"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/retry"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/clissh/cmd"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
	"github.com/deckhouse/lib-connection/pkg/ssh/utils"
)

var (
	_ connection.ReverseTunnel = &ReverseTunnel{}
	_ utils.TunnelBackend      = &tunnelBackend{}
)

// tunnelProcess is a single `ssh -R` invocation. Its exit is reported on done
// exactly once; the buffer guarantees the reporting goroutine never blocks and
// never leaks, regardless of whether anyone is listening.
type tunnelProcess struct {
	id   int
	cmd  *exec.Cmd
	done chan error
}

// ReverseTunnel keeps one cli-ssh reverse tunnel alive. Restarting and stop
// signaling live in utils.TunnelSupervisor; this type only knows how to start,
// observe and kill the ssh process (the utils.TunnelBackend part).
type ReverseTunnel struct {
	settings settings.Settings

	Session *session.Session
	Address string

	mu         sync.Mutex
	proc       *tunnelProcess
	supervisor *utils.TunnelSupervisor
}

func NewReverseTunnel(sett settings.Settings, sess *session.Session, address string) *ReverseTunnel {
	return &ReverseTunnel{
		settings: sett,
		Session:  sess,
		Address:  address,
	}
}

func (t *ReverseTunnel) Up() error {
	return t.startProcess(context.Background())
}

func (t *ReverseTunnel) UpCtx(ctx context.Context) error {
	return t.startProcess(ctx)
}

// startProcess spawns the ssh process and registers it as current. The ctx
// check under mu closes the shutdown race: once Stop has canceled the
// supervisor context, no new process can be registered, so nothing can
// outlive Stop.
func (t *ReverseTunnel) startProcess(ctx context.Context) error {
	logger := t.settings.Logger()

	t.mu.Lock()
	defer t.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("reverse tunnel is shutting down: %w", err)
	}

	if t.proc != nil {
		logger.DebugContext(ctx, fmt.Sprintf("[%d] Reverse tunnel already up\n", t.proc.id))
		return fmt.Errorf("already up")
	}

	id := rand.Int()
	logger.DebugContext(ctx, fmt.Sprintf("[%d] Start reverse tunnel\n", id))

	sshCmd := cmd.NewSSH(t.settings, t.Session).
		WithArgs(
			"-N", // no command
			"-n", // no stdin
			"-R", t.Address,
		).
		WithExitWhenTunnelFailure(true).
		Cmd(context.Background())

	if err := sshCmd.Start(); err != nil {
		return fmt.Errorf("[%d] Cannot start tunnel ssh command: %w", id, err)
	}

	p := &tunnelProcess{
		id:   id,
		cmd:  sshCmd,
		done: make(chan error, 1),
	}

	go func() {
		logger.DebugContext(ctx, fmt.Sprintf("[%d] Reverse tunnel started. Waiting for tunnel to stop...\n", p.id))
		p.done <- p.cmd.Wait()
		logger.DebugContext(ctx, fmt.Sprintf("[%d] Reverse tunnel process exited\n", p.id))
	}()

	t.proc = p

	return nil
}

// stopProcess kills the current ssh process, if any.
func (t *ReverseTunnel) stopProcess() {
	logger := t.settings.Logger()
	ctx := context.Background()

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.proc == nil {
		logger.DebugContext(ctx, "Reverse tunnel already stopped\n")
		return
	}

	logger.DebugContext(ctx, fmt.Sprintf("[%d] Stop reverse tunnel\n", t.proc.id))

	if t.proc.cmd.Process != nil {
		if err := t.proc.cmd.Process.Kill(); err != nil {
			logger.DebugContext(ctx, fmt.Sprintf("[%d] Cannot kill process: %v\n", t.proc.id, err))
		}
	}

	t.proc = nil
}

// tunnelBackend adapts ReverseTunnel + the health checker to utils.TunnelBackend.
type tunnelBackend struct {
	tunnel  *ReverseTunnel
	checker connection.ReverseTunnelChecker
}

func (b *tunnelBackend) StartTunnel(ctx context.Context) error {
	return b.tunnel.startProcess(ctx)
}

func (b *tunnelBackend) StopTunnel() {
	b.tunnel.stopProcess()
}

func (b *tunnelBackend) TunnelDone() <-chan error {
	b.tunnel.mu.Lock()
	defer b.tunnel.mu.Unlock()

	if b.tunnel.proc == nil {
		return nil
	}
	return b.tunnel.proc.done
}

func (b *tunnelBackend) CheckTunnel(ctx context.Context) bool {
	logger := b.tunnel.settings.Logger()

	logger.DebugContext(ctx, "Start Check reverse tunnel\n")

	err := retry.NewSilentLoop("Check reverse tunnel", 5, 1*time.Second).RunContext(ctx, func() error {
		out, err := b.checker.CheckTunnel(ctx)
		if err != nil {
			logger.DebugContext(ctx, fmt.Sprintf("Cannot check ssh tunnel: '%v': stderr: '%s'\n", err, out))
			return err
		}

		return nil
	})

	if err != nil {
		logger.DebugContext(ctx, fmt.Sprintf("Tunnel check timeout, last error: %v\n", err))
		return false
	}

	logger.DebugContext(ctx, "Tunnel check successful!\n")
	return true
}

func (t *ReverseTunnel) StartHealthMonitor(ctx context.Context, checker connection.ReverseTunnelChecker, killer connection.ReverseTunnelKiller) {
	sup := utils.NewTunnelSupervisor(
		&tunnelBackend{tunnel: t, checker: checker},
		killer,
		t.settings.Logger(),
	)

	t.mu.Lock()

	old := t.supervisor
	t.supervisor = sup

	t.mu.Unlock()

	if old != nil {
		old.Stop()
	}

	sup.Start(ctx)
}

func (t *ReverseTunnel) Stop() {
	t.mu.Lock()

	sup := t.supervisor
	t.supervisor = nil

	t.mu.Unlock()

	if sup != nil {
		sup.Stop()
	}

	t.stopProcess()
}

func (t *ReverseTunnel) String() string {
	return fmt.Sprintf("%s:%s", "R", t.Address)
}
