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

	sshtesting "github.com/deckhouse/lib-connection/pkg/ssh/gossh/testing"
)

func TestTunnel(t *testing.T) {
	test := sshtesting.ShouldNewTest(t, "TestTunnel")

	sshClient, container := startContainerAndClientWithContainer(t, test, sshtesting.WithWriteSSHDConfig())
	sshClient.WithLoopsParams(ClientLoopsParams{
		NewSession: retry.NewEmptyParams(
			retry.WithAttempts(5),
			retry.WithWait(250*time.Millisecond),
		),
	})

	// we don't have /opt/deckhouse in the container, so we should create it before start any UploadScript with sudo
	err := container.Container.CreateDeckhouseDirs()
	require.NoError(t, err, "could not create deckhouse dirs")

	remoteServerPort := sshtesting.RandPortExclude([]int{container.Container.RemotePort()})
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

	runRemoteServerSession, err := sshClient.NewSession()
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
		localServerPort := sshtesting.RandPortExclude(localsReservedPorts)
		localsReservedPorts = append(localsReservedPorts, localServerPort)

		localServerInvalidPort := sshtesting.RandInvalidPortExclude(localsReservedPorts)
		remoteServerInvalidPort := sshtesting.RandPortExclude([]int{remoteServerPort, container.Container.RemotePort()})

		cases := []struct {
			title string

			localPort  int
			remotePort int

			wantErr bool
			err     string
		}{
			{
				title:      "Tunnel, success",
				localPort:  localServerPort,
				remotePort: remoteServerPort,
				wantErr:    false,
			},
			{
				title:      "Invalid address",
				localPort:  localServerPort,
				remotePort: remoteServerInvalidPort,
				wantErr:    true,
				err:        "invalid address must be 'remote_bind:remote_port:local_bind:local_port'",
			},
			{
				title:      "Invalid local bind",
				localPort:  localServerInvalidPort,
				remotePort: remoteServerPort,
				wantErr:    true,
				err:        fmt.Sprintf("failed to listen local on 127.0.0.1:%d", localServerInvalidPort),
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				address := tunnelAddressString(c.localPort, c.remotePort)
				tun := NewTunnel(sshClient, address)
				err = tun.Up()
				registerStopTunnel(t, tun)

				if c.wantErr {
					require.Error(t, err)
					require.Contains(t, err.Error(), c.err)
				}

				checkLocalTunnel(t, test, localServerPort, false)

				// try to up again: expectiong error
				err = tun.Up()
				require.Error(t, err)
				require.Equal(t, err.Error(), "already up")
			})
		}
	})

	t.Run("Health monitor", func(t *testing.T) {
		upTunnelWithMonitor := func(t *testing.T, address string) chan error {
			tun := NewTunnel(sshClient, address)
			err = tun.Up()
			registerStopTunnel(t, tun)

			// starting HealthMonitor
			errChan := make(chan error, 10)
			go tun.HealthMonitor(errChan)

			t.Cleanup(func() {
				close(errChan)
			})

			return errChan
		}

		t.Run("Dial to unreacheble host", func(t *testing.T) {
			incorrectHost := sshtesting.IncorrectHost()
			incorrectPort := sshtesting.RandPort()
			localServerPort := sshtesting.RandPortExclude(localsReservedPorts)
			localsReservedPorts = append(localsReservedPorts, localServerPort)

			remoteStr := fmt.Sprintf("%s:%d", incorrectHost, incorrectPort)
			address := fmt.Sprintf("%s:127.0.0.1:%d", remoteStr, localServerPort)

			errChan := upTunnelWithMonitor(t, address)

			checkLocalTunnel(t, test, localServerPort, true)

			msg := ""
			select {
			case m, ok := <-errChan:
				if !ok {
					msg = "monitor channel closed"
				} else {
					if m != nil {
						msg = m.Error()
					}
				}

			default:
				msg = ""
			}

			require.Contains(t, msg, fmt.Sprintf("Cannot dial to %s", remoteStr), "got: '%s'", msg)
		})

		t.Run("Restart connection", func(t *testing.T) {
			localServerPort := sshtesting.RandPortExclude(localsReservedPorts)
			localsReservedPorts = append(localsReservedPorts, localServerPort)

			upTunnelWithMonitor(t, tunnelAddressString(localServerPort, remoteServerPort))

			checkLocalTunnel(t, test, localServerPort, false)

			restartSleep := 5 * time.Second
			upMonitorSleep := 2 * time.Second

			test.Logger.InfoF(
				"Disconnect (fail connection between server and client) case. Wait %s before connect. Wait %s before check",
				restartSleep.String(),
				upMonitorSleep.String(),
			)

			err = container.Container.FailAndUpConnection(restartSleep)
			require.NoError(t, err)

			time.Sleep(upMonitorSleep)

			checkLocalTunnel(t, test, localServerPort, false)
		})
	})
}

func checkLocalTunnel(t *testing.T, test *sshtesting.Test, localServerPort int, wantError bool) {
	url := fmt.Sprintf("http://127.0.0.1:%d", localServerPort)

	requestLoop := retry.NewEmptyParams(
		retry.WithName(fmt.Sprintf("Check local tunnel available by %s", url)),
		retry.WithAttempts(10),
		retry.WithWait(500*time.Millisecond),
		retry.WithLogger(test.Logger),
	)

	_, err := sshtesting.DoGetRequest(
		url,
		requestLoop,
		sshtesting.NewPrefixLogger(test.Logger).WithPrefix(test.TestName),
	)

	assert := require.NoError
	if wantError {
		assert = require.Error
	}

	assert(t, err, "check local tunnel. Want error %v", wantError)
}
