// Copyright 2025 Flant JSC
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
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"strings"
	"sync"

	"github.com/deckhouse/lib-dhctl/pkg/retry"
	"github.com/pkg/errors"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/ssh/utils"
)

var (
	_ connection.ReverseTunnel = &ReverseTunnel{}
	_ utils.TunnelBackend      = &tunnelBackend{}
)

// tunnelListener is a single remote listener over the established ssh
// connection. Its termination is reported on done exactly once; the buffer
// guarantees the accept loop never blocks on the send and never leaks,
// regardless of whether anyone is listening.
type tunnelListener struct {
	id       int
	listener net.Listener
	done     chan error
}

// ReverseTunnel keeps one go-ssh reverse tunnel alive. Restarting and stop
// signaling live in utils.TunnelSupervisor; this type only knows how to open,
// observe and close the remote listener (the utils.TunnelBackend part).
type ReverseTunnel struct {
	sshClient *Client
	address   string

	mu         sync.Mutex
	tun        *tunnelListener
	supervisor *utils.TunnelSupervisor
}

func NewReverseTunnel(sshClient *Client, address string) *ReverseTunnel {
	return &ReverseTunnel{
		sshClient: sshClient,
		address:   address,
	}
}

func (t *ReverseTunnel) Up() error {
	return t.startListener(context.Background())
}

func (t *ReverseTunnel) UpCtx(ctx context.Context) error {
	return t.startListener(ctx)
}

// startListener opens the remote listener and registers it as current.
// The ctx check under mu closes the shutdown race:
// once Stop has canceled the supervisor context, no new listener can be registered,
// so nothing can outlive Stop.
func (t *ReverseTunnel) startListener(ctx context.Context) error {
	logger := t.sshClient.settings.Logger()

	t.mu.Lock()
	defer t.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("reverse tunnel is shutting down: %w", err)
	}

	if t.tun != nil {
		logger.DebugF("[%d] Reverse tunnel already up\n", t.tun.id)
		return fmt.Errorf("already up")
	}

	parts := strings.Split(t.address, ":")
	if len(parts) != 4 {
		return fmt.Errorf("invalid address must be 'remote_bind:remote_port:local_bind:local_port': %s", t.address)
	}

	remoteBind, remotePort, localBind, localPort := parts[0], parts[1], parts[2], parts[3]

	id := rand.Int()

	logger.DebugF("[%d] Remote bind: %s remote port: %s local bind: %s local port: %s\n", id, remoteBind, remotePort, localBind, localPort)
	logger.DebugF("[%d] Start reverse tunnel\n", id)

	remoteAddress := net.JoinHostPort(remoteBind, remotePort)
	localAddress := net.JoinHostPort(localBind, localPort)

	// reverse listen on remote server port
	sshClient, err := t.sshClient.snapshotSSHClient()
	if err != nil {
		return err
	}

	listener, err := sshClient.Listen("tcp", remoteAddress)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to listen remote on %s", remoteAddress))
	}

	logger.DebugF("[%d] Listen remote %s successful\n", id, remoteAddress)

	tun := &tunnelListener{
		id:       id,
		listener: listener,
		done:     make(chan error, 1),
	}

	go t.acceptTunnelConnection(tun, localAddress)

	t.tun = tun

	return nil
}

// stopListener closes the current remote listener, if any.
// Closing it also frees the port on the server side.
func (t *ReverseTunnel) stopListener() {
	logger := t.sshClient.settings.Logger()

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.tun == nil {
		logger.DebugF("Reverse tunnel already stopped\n")
		return
	}

	logger.DebugF("[%d] Stop reverse tunnel\n", t.tun.id)

	err := t.tun.listener.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		logger.InfoF("[%d] Cannot close remote listener: %s\n", t.tun.id, err.Error())
	}

	t.tun = nil
}

// acceptTunnelConnection serves the listener until the first fatal error,
// which it reports on tun.done (single buffered send — never blocks).
func (t *ReverseTunnel) acceptTunnelConnection(tun *tunnelListener, localAddress string) {
	logger := t.sshClient.settings.Logger()
	for {
		client, err := tun.listener.Accept()
		if err != nil {
			tun.done <- fmt.Errorf("Accept(): %s", err.Error())
			return
		}

		logger.DebugF("[%d] connection accepted. Try to connect to local %s\n", tun.id, localAddress)

		local, err := net.Dial("tcp", localAddress)
		if err != nil {
			tun.done <- fmt.Errorf("Cannot dial to %s: %s", localAddress, err.Error())
			return
		}

		logger.DebugF("[%d] Connected to local %s\n", tun.id, localAddress)

		// handle the connection in another goroutine, so we can support multiple concurrent
		// connections on the same port
		go t.handleClient(tun.id, client, local)
	}
}

func (t *ReverseTunnel) handleClient(id int, client net.Conn, remote net.Conn) {
	logger := t.sshClient.settings.Logger()

	defer func() {
		err := client.Close()
		if err != nil {
			logger.DebugF("[%d] Cannot close connection: %s\n", id, err)
		}
	}()

	chDone := make(chan struct{}, 2)

	// Start remote -> local data transfer
	go func() {
		_, err := io.Copy(client, remote)
		if err != nil {
			logger.WarnF(fmt.Sprintf("[%d] Error while copy remote->local: %s\n", id, err))
		}
		chDone <- struct{}{}
	}()

	// Start local -> remote data transfer
	go func() {
		_, err := io.Copy(remote, client)
		if err != nil {
			logger.WarnF(fmt.Sprintf("[%d] Error while copy local->remote: %s\n", id, err))
		}
		chDone <- struct{}{}
	}()

	<-chDone
}

// tunnelBackend adapts ReverseTunnel + the health checker to utils.TunnelBackend.
type tunnelBackend struct {
	tunnel  *ReverseTunnel
	checker connection.ReverseTunnelChecker
}

func (b *tunnelBackend) StartTunnel(ctx context.Context) error {
	return b.tunnel.startListener(ctx)
}

func (b *tunnelBackend) StopTunnel() {
	b.tunnel.stopListener()
}

func (b *tunnelBackend) TunnelDone() <-chan error {
	b.tunnel.mu.Lock()
	defer b.tunnel.mu.Unlock()

	if b.tunnel.tun == nil {
		return nil
	}

	return b.tunnel.tun.done
}

func (b *tunnelBackend) CheckTunnel(ctx context.Context) bool {
	logger := b.tunnel.sshClient.settings.Logger()

	logger.DebugF("Start Check reverse tunnel\n")

	checkLoopParams := b.tunnel.sshClient.loopsParams.CheckReverseTunnel
	checkLoopParams = retry.SafeCloneOrNewParams(checkLoopParams, defaultReverseTunnelParamsOps...).
		Clone(
			retry.WithName("Check reverse tunnel"),
			retry.WithLogger(logger),
		)

	err := retry.NewSilentLoopWithParams(checkLoopParams).RunContext(ctx, func() error {
		out, err := b.checker.CheckTunnel(ctx)
		if err != nil {
			logger.DebugF("Cannot check ssh tunnel: '%v': stderr: '%s'\n", err, out)
			return err
		}

		return nil
	})

	if err != nil {
		logger.DebugF("Tunnel check timeout, last error: %v\n", err)
		return false
	}

	logger.DebugF("Tunnel check successful!\n")
	return true
}

func defaultKiller(killer connection.ReverseTunnelKiller) connection.ReverseTunnelKiller {
	if killer == nil {
		return utils.EmptyReverseTunnelKiller{}
	}

	return killer
}

func (t *ReverseTunnel) StartHealthMonitor(ctx context.Context, checker connection.ReverseTunnelChecker, killer connection.ReverseTunnelKiller) {
	sup := utils.NewTunnelSupervisor(
		&tunnelBackend{tunnel: t, checker: checker},
		defaultKiller(killer),
		t.sshClient.settings.Logger(),
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

	t.stopListener()
}

func (t *ReverseTunnel) String() string {
	return fmt.Sprintf("%s:%s", "R", t.address)
}
