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

type tunnelWaitResult struct {
	id  int
	err error
}

type ReverseTunnel struct {
	sshClient *Client
	address   string

	tunMutex sync.Mutex

	started        bool
	stopCh         chan struct{}
	remoteListener net.Listener

	errorCh chan tunnelWaitResult
}

func NewReverseTunnel(sshClient *Client, address string) *ReverseTunnel {
	return &ReverseTunnel{
		sshClient: sshClient,
		address:   address,
		errorCh:   make(chan tunnelWaitResult),
	}
}

func (t *ReverseTunnel) Up() error {
	_, err := t.upNewTunnel(-1)
	return err
}

func (t *ReverseTunnel) upNewTunnel(oldId int) (int, error) {
	t.tunMutex.Lock()
	defer t.tunMutex.Unlock()

	logger := t.sshClient.settings.Logger()

	if t.started {
		logger.DebugF("[%d] Reverse tunnel already up\n", oldId)
		return -1, fmt.Errorf("already up")
	}

	id := rand.Int()

	parts := strings.Split(t.address, ":")
	if len(parts) != 4 {
		return -1, fmt.Errorf("invalid address must be 'remote_bind:remote_port:local_bind:local_port': %s", t.address)
	}

	remoteBind, remotePort, localBind, localPort := parts[0], parts[1], parts[2], parts[3]

	logger.DebugF("[%d] Remote bind: %s remote port: %s local bind: %s local port: %s\n", id, remoteBind, remotePort, localBind, localPort)

	logger.DebugF("[%d] Start reverse tunnel\n", id)

	remoteAddress := net.JoinHostPort(remoteBind, remotePort)
	localAddress := net.JoinHostPort(localBind, localPort)

	// reverse listen on remote server port
	listener, err := t.sshClient.GetClient().Listen("tcp", remoteAddress)
	if err != nil {
		return -1, errors.Wrap(err, fmt.Sprintf("failed to listen remote on %s", remoteAddress))
	}

	logger.DebugF("[%d] Listen remote %s successful\n", id, remoteAddress)

	go t.acceptTunnelConnection(id, localAddress, listener)

	t.remoteListener = listener
	t.started = true

	return id, nil
}

func (t *ReverseTunnel) acceptTunnelConnection(id int, localAddress string, listener net.Listener) {
	logger := t.sshClient.settings.Logger()
	for {
		client, err := listener.Accept()
		if err != nil {
			e := fmt.Errorf("Accept(): %s", err.Error())
			t.errorCh <- tunnelWaitResult{
				id:  id,
				err: e,
			}
			return
		}

		logger.DebugF("[%d] connection accepted. Try to connect to local %s\n", id, localAddress)

		local, err := net.Dial("tcp", localAddress)
		if err != nil {
			e := fmt.Errorf("Cannot dial to %s: %s", localAddress, err.Error())
			t.errorCh <- tunnelWaitResult{
				id:  id,
				err: e,
			}
			return
		}

		logger.DebugF("[%d] Connected to local %s\n", id, localAddress)

		// handle the connection in another goroutine, so we can support multiple concurrent
		// connections on the same port
		go t.handleClient(id, client, local)
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

func (t *ReverseTunnel) isStarted() bool {
	t.tunMutex.Lock()
	defer t.tunMutex.Unlock()
	r := t.started
	return r
}

func (t *ReverseTunnel) tryToRestart(ctx context.Context, id int, killer connection.ReverseTunnelKiller) (int, error) {
	t.stop(id, false)
	t.sshClient.settings.Logger().DebugF("[%d] Kill tunnel\n", id)
	// (k EmptyReverseTunnelKiller) KillTunnel won't return error anyways, so we couldn't check return values
	killer.KillTunnel(ctx)
	return t.upNewTunnel(id)
}

func (t *ReverseTunnel) StartHealthMonitor(ctx context.Context, checker connection.ReverseTunnelChecker, _ connection.ReverseTunnelKiller) {
	t.tunMutex.Lock()
	t.stopCh = make(chan struct{})
	t.tunMutex.Unlock()

	logger := t.sshClient.settings.Logger()

	// in go ssh implementation we do not need separate script for kill tunnel from server-side
	// because listener.Close() close tunnel in the server side
	// but we need to backward compatibility with cli ssh
	killer := utils.EmptyReverseTunnelKiller{}

	checkReverseTunnel := func(id int) bool {
		logger.DebugF("[%d] Start Check reverse tunnel\n", id)

		checkLoopParams := t.sshClient.loopsParams.CheckReverseTunnel
		checkLoopParams = retry.SafeCloneOrNewParams(checkLoopParams, defaultReverseTunnelParamsOps...).
			WithName("Check reverse tunnel").
			WithLogger(logger)

		err := retry.NewSilentLoopWithParams(checkLoopParams).RunContext(ctx, func() error {
			out, err := checker.CheckTunnel(ctx)
			if err != nil {
				logger.DebugF("[%d] Cannot check ssh tunnel: '%v': stderr: '%s'\n", id, err, out)
				return err
			}

			return nil
		})

		if err != nil {
			logger.DebugF("[%d] Tunnel check timeout, last error: %v\n", id, err)
			return false
		}

		logger.DebugF("[%d] Tunnel check successful!\n", id)
		return true
	}

	go func() {
		logger.DebugLn("Start health monitor")
		// we need chan for restarting because between restarting we can get stop signal
		restartCh := make(chan int, 1024)
		id := -1
		restartsCount := 0
		restart := func(id int) {
			logger.DebugF("[%d] Send restart signal\n", id)
			restartCh <- id
			logger.DebugF("[%d] Signal was sent. Chan len: %d\n", id, len(restartCh))
		}
		for {

			if !checkReverseTunnel(id) {
				go restart(id)
			}

			select {
			case <-t.stopCh:
				logger.DebugLn("Stop health monitor")
				return
			case oldId := <-restartCh:
				restartsCount++
				logger.DebugF("[%d] Restart signal was received: restarts count %d\n", oldId, restartsCount)

				if restartsCount > 1024 {
					panic("Reverse tunnel restarts count exceeds 1024")
				}

				newId, err := t.tryToRestart(ctx, oldId, killer)
				if err != nil {
					logger.DebugF("[%d] Restart failed with error: %v\n", oldId, err)
					go restart(oldId)
					continue
				}
				logger.DebugF("[%d] Restart successful. New id %d\n", oldId, newId)
				id = newId
				restartsCount = 0
			case err := <-t.errorCh:
				id = err.id
				logger.DebugF("[%d] Tunnel was stopped with error '%v'. Try restart fully\n", id, err.err)
				started := t.isStarted()
				if started {
					logger.DebugF("[%d] Tunnel already up. Skip restarting\n", id)
					continue
				}

				go restart(id)
				continue
			}
		}
	}()
}

func (t *ReverseTunnel) Stop() {
	t.stop(-1, true)
}

func (t *ReverseTunnel) stop(id int, full bool) {
	t.tunMutex.Lock()
	defer t.tunMutex.Unlock()

	logger := t.sshClient.settings.Logger()

	if !t.started {
		logger.DebugF("[%d] Reverse tunnel already stopped\n", id)
		return
	}

	logger.DebugF("[%d] Stop reverse tunnel\n", id)
	defer logger.DebugF("[%d] End stop reverse tunnel\n", id)

	if full && t.stopCh != nil {
		logger.DebugF("[%d] Stop reverse tunnel health monitor\n", id)
		t.stopCh <- struct{}{}
	}

	err := t.remoteListener.Close()
	if err != nil {
		logger.WarnF("[%d] Cannot close remote listener: %s\n", id, err.Error())
	}

	t.remoteListener = nil
	t.started = false
}

func (t *ReverseTunnel) String() string {
	return fmt.Sprintf("%s:%s", "R", t.address)
}
