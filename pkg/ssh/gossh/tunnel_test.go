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
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/retry"
	ssh "github.com/deckhouse/lib-gossh"
	"github.com/stretchr/testify/require"

	"github.com/deckhouse/lib-connection/pkg/tests"
)

func TestTunnel(t *testing.T) {
	test := tests.ShouldNewTest(t, "TestTunnel")

	sshClient, container := startContainerAndClientWithContainer(t, test)
	sshClient.WithLoopsParams(ClientLoopsParams{
		NewSession: retry.NewEmptyParams(
			retry.WithAttempts(5),
			retry.WithWait(250*time.Millisecond),
		),
	})

	// we don't have /opt/deckhouse in the container, so we should create it before start any UploadScript with sudo
	err := container.Container.CreateDeckhouseDirs()
	require.NoError(t, err, "could not create deckhouse dirs")

	remoteServerPort := tests.RandPortExclude([]int{container.Container.RemotePort()})
	remoteServerScript := fmt.Sprintf(`#!/bin/bash
while true ; do {
  echo -ne "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n" ;
  echo -n "OK";
} | nc -l -p %d ;
done`, remoteServerPort)

	const remoteServerFile = "/tmp/server.sh"
	localServerFile := test.MustCreateTmpFile(t, remoteServerScript, true, "remote_server", "server.sh")

	err = sshClient.File().Upload(context.TODO(), localServerFile, remoteServerFile)
	require.NoError(t, err)

	runRemoteServerSession, err := sshClient.NewSSHSession()
	require.NoError(t, err)

	t.Cleanup(func() {
		err := runRemoteServerSession.Signal(ssh.SIGKILL)
		if err != nil {
			test.Logger.ErrorF("error killing remote server: %v", err)
		}
		err = runRemoteServerSession.Close()
		if err != nil {
			test.Logger.ErrorF("error closing remote server session: %v", err)
		}
	})

	err = runRemoteServerSession.Start(remoteServerFile)
	require.NoError(t, err, "error starting remote server")

	localsReservedPorts := []int{container.LocalPort()}

	t.Run("Tunnel to container", func(t *testing.T) {
		localServerPort := tests.RandPortExclude(localsReservedPorts)
		localsReservedPorts = append(localsReservedPorts, localServerPort)

		// localServerInvalidPort := sshtesting.RandInvalidPortExclude(localsReservedPorts)
		remoteServerInvalidPort := tests.RandPortExclude([]int{remoteServerPort, container.Container.RemotePort()})

		cases := []struct {
			title string

			address string

			wantErr bool
			err     string
		}{
			{
				title:   "Tunnel, success",
				address: tunnelAddressString(localServerPort, remoteServerPort),
				wantErr: false,
			},
			{
				title:   "Invalid address",
				address: fmt.Sprintf("%d:127.0.0.1:%d", remoteServerInvalidPort, localServerPort),
				wantErr: true,
				err:     "invalid address must be 'remote_bind:remote_port:local_bind:local_port'",
			},
			{
				title:   "Invalid local bind",
				address: tunnelAddressString(22, remoteServerPort),
				wantErr: true,
				err:     fmt.Sprintf("failed to listen local on 127.0.0.1:%d", 22),
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				test.RunSubTestParallel(t)

				ctx := context.TODO()

				tun := NewTunnel(sshClient, c.address)
				err = tun.Up(ctx)
				registerStopTunnel(t, tun)

				if !c.wantErr {
					checkLocalTunnel(t, test, localServerPort, false)
					// try to up again: expecting error
					err = tun.Up(ctx)
					require.Error(t, err)
					require.Equal(t, err.Error(), "already up")
				} else {
					require.Error(t, err)
					require.Contains(t, err.Error(), c.err)
				}
			})
		}
	})

	t.Run("Health monitor", func(t *testing.T) {
		upTunnelWithMonitor := func(t *testing.T, ctx context.Context, address string) chan error {
			tun := NewTunnel(sshClient, address)
			err = tun.Up(ctx)
			registerStopTunnel(t, tun)

			// starting HealthMonitor
			errChan := make(chan error, 10)
			go tun.HealthMonitor(errChan)

			t.Cleanup(func() {
				close(errChan)
			})

			return errChan
		}

		waitErr := func(errChan chan error) string {
			msg := ""
			m, ok := <-errChan
			if !ok {
				msg = "monitor channel closed"
			} else if m != nil {
				msg = m.Error()
			}

			return msg
		}

		t.Run("Dial to unreacheble host", func(t *testing.T) {
			incorrectHost := tests.IncorrectHost()
			incorrectPort := tests.RandPort()
			localServerPort := tests.RandPortExclude(localsReservedPorts)
			localsReservedPorts = append(localsReservedPorts, localServerPort)

			remoteStr := fmt.Sprintf("%s:%d", incorrectHost, incorrectPort)
			address := fmt.Sprintf("%s:127.0.0.1:%d", remoteStr, localServerPort)

			errChan := upTunnelWithMonitor(t, context.TODO(), address)

			checkLocalTunnel(t, test, localServerPort, true)

			msg := waitErr(errChan)

			require.Contains(t, msg, fmt.Sprintf("Cannot dial to %s", remoteStr), "got: '%s'", msg)
		})
	})
}

func checkLocalTunnel(t *testing.T, test *tests.Test, localServerPort int, wantError bool) {
	url := fmt.Sprintf("http://127.0.0.1:%d", localServerPort)

	requestLoop := retry.NewEmptyParams(
		retry.WithName("Check local tunnel available by %s", url),
		retry.WithAttempts(10),
		retry.WithWait(500*time.Millisecond),
		retry.WithLogger(test.Logger),
	)

	_, err := tests.DoGetRequest(
		url,
		requestLoop,
		tests.NewPrefixLogger(test.Logger).WithPrefix(test.FullName()),
	)

	assert := require.NoError
	if wantError {
		assert = require.Error
	}

	assert(t, err, "check local tunnel. Want error %v", wantError)
}
