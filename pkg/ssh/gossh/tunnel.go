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
)

type Tunnel struct {
	sshClient *Client
	address   string

	tunMutex sync.Mutex

	started        bool
	stopCh         chan struct{}
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
	logger := t.sshClient.settings.Logger()

	t.tunMutex.Lock()
	defer t.tunMutex.Unlock()

	if t.started {
		logger.DebugF("[%d] Tunnel already up\n", oldId)
		return -1, fmt.Errorf("already up")
	}

	id := rand.Int()

	parts := strings.Split(t.address, ":")
	if len(parts) != 4 {
		return -1, fmt.Errorf("invalid address must be 'remote_bind:remote_port:local_bind:local_port': %s", t.address)
	}

	remoteBind, remotePort, localBind, localPort := parts[0], parts[1], parts[2], parts[3]

	logger.DebugF("[%d] Remote bind: %s remote port: %s local bind: %s local port: %s\n", id, remoteBind, remotePort, localBind, localPort)

	logger.DebugF("[%d] Start tunnel\n", id)

	remoteAddress := net.JoinHostPort(remoteBind, remotePort)
	localAddress := net.JoinHostPort(localBind, localPort)

	listener, err := net.Listen("tcp", localAddress)
	if err != nil {
		return -1, errors.Wrap(err, fmt.Sprintf("failed to listen local on %s", localAddress))
	}

	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		_ = listener.Close()
		return -1, fmt.Errorf("Failed to up tunnel: got not TCPListner")
	}

	logger.DebugF("[%d] Listen remote on %s successful", id, localAddress)

	logger.DebugF("[%d] Tunnel %s up. Starting accept tunnel connection", id, localAddress)

	go t.monitorContext(ctx, id)
	go t.acceptTunnelConnection(ctx, id, remoteAddress, tcpListener)

	t.remoteListener = listener
	t.started = true

	return id, nil
}

func (t *Tunnel) remoteConn(ctx context.Context, remoteAddress string) (net.Conn, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	remoteConn, err := t.sshClient.GetClient().DialContext(cctx, "tcp", remoteAddress)
	if err != nil {
		return nil, err
	}

	return remoteConn, nil
}

func (t *Tunnel) monitorContext(ctx context.Context, id int) {
	<-ctx.Done()
	t.stop(id, true)
	t.errorCh <- ctx.Err()
}

func (t *Tunnel) acceptNext(ctx context.Context, id int, remoteAddress string, listener *net.TCPListener) (net.Conn, net.Conn, error) {
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
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

func (t *Tunnel) acceptTunnelConnection(ctx context.Context, id int, remoteAddress string, listener *net.TCPListener) {
	for {
		// todo handle listener closed case and break cycle
		localConn, remoteConn, err := t.acceptNext(ctx, id, remoteAddress, listener)
		if err != nil {
			t.errorCh <- err

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
					t.errorCh <- err
				}
			}()

			_, err := io.Copy(localConn, remoteConn)
			if err != nil {
				t.errorCh <- err
			}
		}()
	}
}

func (t *Tunnel) HealthMonitor(errorOutCh chan<- error) {
	logger := t.sshClient.settings.Logger()

	defer logger.DebugF("Tunnel health monitor stopped\n")
	logger.DebugF("Tunnel health monitor started\n")

	t.stopCh = make(chan struct{}, 1)

	for {
		select {
		case err := <-t.errorCh:
			errorOutCh <- err
		case <-t.stopCh:
			if !govalue.Nil(t.remoteListener) {
				_ = t.remoteListener.Close()
			}
			return
		}
	}
}

func (t *Tunnel) Stop() {
	t.stop(-1, true)
}

func (t *Tunnel) stop(id int, full bool) {
	logger := t.sshClient.settings.Logger()

	t.tunMutex.Lock()
	defer t.tunMutex.Unlock()

	if !t.started {
		logger.DebugF("[%d] Tunnel already stopped\n", id)
		return
	}

	logger.DebugF("[%d] Stop tunnel\n", id)
	defer logger.DebugF("[%d] End stop tunnel\n", id)

	if full && t.stopCh != nil {
		logger.DebugF("[%d] Stop tunnel health monitor\n", id)
		t.stopCh <- struct{}{}
	}

	err := t.remoteListener.Close()
	if err != nil {
		logger.DebugF("[%d] Cannot close listener: %s\n", id, err.Error())
	}

	t.remoteListener = nil
	t.started = false
}

func (t *Tunnel) String() string {
	return fmt.Sprintf("%s:%s", "L", t.address)
}

func (t *Tunnel) debug(format string, args ...interface{}) {
	t.sshClient.settings.Logger().DebugF(format, args...)
}
