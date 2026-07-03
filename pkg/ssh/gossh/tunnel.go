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
	"time"

	"github.com/name212/govalue"
	"github.com/pkg/errors"

	connection "github.com/deckhouse/lib-connection/pkg"
)

var (
	_ connection.Tunnel = &Tunnel{}
)

type Tunnel struct {
	globalMu sync.Mutex

	sshClient *Client
	address   string

	started bool

	stopCh chan struct{}

	tunMutex       sync.RWMutex
	remoteListener net.Listener

	errorCh chan error
}

func NewTunnel(sshClient *Client, address string) *Tunnel {
	return &Tunnel{
		sshClient: sshClient,
		address:   address,
		errorCh:   make(chan error, 10),
	}
}

func (t *Tunnel) Up(ctx context.Context) error {
	_, err := t.upNewTunnel(ctx, -1)
	return err
}

func (t *Tunnel) upNewTunnel(ctx context.Context, oldId int) (int, error) {
	t.globalMu.Lock()
	defer t.globalMu.Unlock()

	if t.started {
		t.debugWithID(oldId, "[%d] Tunnel already up")
		return -1, fmt.Errorf("already up")
	}

	id := rand.Int()

	parts := strings.Split(t.address, ":")
	if len(parts) != 4 {
		return -1, fmt.Errorf("invalid address must be 'remote_bind:remote_port:local_bind:local_port': %s", t.address)
	}

	remoteBind, remotePort, localBind, localPort := parts[0], parts[1], parts[2], parts[3]

	t.debugWithID(
		id,
		"Start tunnel. Remote bind: %s remote port: %s local bind: %s local port: %s",
		remoteBind,
		remotePort,
		localBind,
		localPort,
	)

	remoteAddress := net.JoinHostPort(remoteBind, remotePort)
	localAddress := net.JoinHostPort(localBind, localPort)

	listener, err := net.Listen("tcp", localAddress)
	if err != nil {
		return -1, fmt.Errorf("failed to listen local on %s: %w", localAddress, err)
	}

	t.setListener(listener)

	t.debugWithID(id, "Listen remote on %s successful. Starting monitors...", localAddress)

	if ctx.Done() != nil {
		go t.monitorContext(ctx, id)
	}
	go t.acceptTunnelConnection(ctx, id, remoteAddress)

	t.started = true

	return id, nil
}

func (t *Tunnel) dialRemote(ctx context.Context, remoteAddress string) (net.Conn, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	sshClient, err := t.sshClient.snapshotSSHClient()
	if err != nil {
		return nil, err
	}

	remoteConn, err := sshClient.DialContext(cctx, "tcp", remoteAddress)
	if err != nil {
		return nil, err
	}

	return remoteConn, nil
}

func (t *Tunnel) remoteConn(ctx context.Context, remoteAddress string) (net.Conn, error) {
	// use cycle for prevent connection refuse error on start

	// no use retry package because silent logger can tee logs to file
	// it is huge for logger
	var lastErr error
	for i := 0; i < 3; i++ {
		conn, err := t.dialRemote(ctx, remoteAddress)
		if err != nil {
			lastErr = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		return conn, nil
	}

	return nil, lastErr
}

func (t *Tunnel) monitorContext(ctx context.Context, id int) {
	done := ctx.Done()
	if done == nil {
		return
	}

	<-done
	t.stop(id)
	t.sendError(ctx.Err())
}

var emptyListenerErr = errors.New("empty listener")

func (t *Tunnel) acceptNext(ctx context.Context, id int, remoteAddress string) (net.Conn, net.Conn, error) {
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
	}

	listener, err := t.getListener()
	if err != nil {
		return nil, nil, err
	}

	localConn, err := listener.Accept()

	if err != nil {
		e := fmt.Errorf("[%d] Accept(): %w", id, err)
		return nil, nil, e
	}

	remoteConn, err := t.remoteConn(ctx, remoteAddress)
	if err != nil {
		_ = localConn.Close()

		e := fmt.Errorf("[%d] Cannot dial to %s: %w", id, remoteAddress, err)
		return nil, nil, e
	}

	return localConn, remoteConn, nil
}

func (t *Tunnel) acceptTunnelConnection(ctx context.Context, id int, remoteAddress string) {
	t.debugWithID(id, "Start accepting tunnel connection")
	defer t.debugWithID(id, "Accepting tunnel connection stopped")

	for {
		localConn, remoteConn, err := t.acceptNext(ctx, id, remoteAddress)
		if err != nil {
			// after stop we can get error on using close connection should not send error
			// it is valid operation
			if errors.Is(err, emptyListenerErr) {
				t.debugWithID(id, "Accept tunnel connection stopped because listener set to nil")
				return
			}

			t.sendError(err)

			if isContextError(err) {
				t.debug("acceptTunnelConnection: got context error return from accept loop", err)
				return
			}

			t.debug("acceptTunnelConnection: %v", err)
			continue
		}

		go func() {
			defer localConn.Close()
			defer remoteConn.Close()
			go func() {
				_, err := io.Copy(remoteConn, localConn)
				if err != nil {
					t.sendError(err)
				}
			}()

			_, err := io.Copy(localConn, remoteConn)
			if err != nil {
				t.sendError(err)
			}
		}()
	}
}

func (t *Tunnel) sendError(err error) {
	if err == nil || t.errorCh == nil {
		return
	}

	select {
	case t.errorCh <- err:
	default:
	}
}

func (t *Tunnel) HealthMonitor(errorOutCh chan<- error) {
	if _, err := t.getListener(); err != nil || !t.started {
		t.debug("Call HealthMonitor. Tunnel stopped")
		errorOutCh <- fmt.Errorf("tunnel stopped")
		return
	}

	defer t.debug("Tunnel health monitor stopped")
	t.debug("Tunnel health monitor started")

	t.stopCh = make(chan struct{}, 1)

	for {
		select {
		case err := <-t.errorCh:
			errorOutCh <- err
		case <-t.stopCh:
			return
		}
	}
}

func (t *Tunnel) Stop() {
	t.stop(-1)
}

func (t *Tunnel) stop(id int) {
	t.globalMu.Lock()
	defer t.globalMu.Unlock()

	if !t.started {
		t.debugWithID(id, "Tunnel already stopped")
		return
	}

	t.debugWithID(id, "Stop tunnel")
	defer t.debugWithID(id, "End stop tunnel")

	if t.stopCh != nil {
		t.debugWithID(id, "Stop tunnel health monitor")
		t.stopCh <- struct{}{}
	}

	listener, err := t.getListener()
	if err == nil {
		t.debugWithID(id, "Close listener")
		err := listener.Close()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.debugWithID(id, "Cannot close listener: %v", id, err)
		}
	}

	t.setListener(nil)
	t.started = false
}

func (t *Tunnel) String() string {
	return fmt.Sprintf("%s:%s", "L", t.address)
}

func (t *Tunnel) setListener(l net.Listener) {
	t.tunMutex.Lock()
	defer t.tunMutex.Unlock()

	t.remoteListener = l
}

func (t *Tunnel) getListener() (net.Listener, error) {
	t.tunMutex.RLock()
	defer t.tunMutex.RUnlock()

	listener := t.remoteListener
	if govalue.Nil(listener) {
		return nil, emptyListenerErr
	}

	return listener, nil
}

func (t *Tunnel) debug(format string, args ...any) {
	t.sshClient.settings.Logger().DebugF(format, args...)
}

func (t *Tunnel) debugWithID(id int, format string, args ...any) {
	if id > 0 {
		format = "[%d] " + format
		args = append([]any{id}, args...)
	}

	t.sshClient.settings.Logger().DebugF(format, args...)
}
