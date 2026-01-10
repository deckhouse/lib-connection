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
	"github.com/stretchr/testify/require"

	sshtesting "github.com/deckhouse/lib-connection/pkg/ssh/gossh/testing"
	"github.com/deckhouse/lib-connection/pkg/ssh/utils"
)

func TestReverseTunnel(t *testing.T) {
	test := sshtesting.ShouldNewTest(t, "TestReverseTunnel")

	sshClient, container := startContainerAndClientWithContainer(t, test, sshtesting.WithWriteSSHDConfig())

	// we don't have /opt/deckhouse in the container, so we should create it before start any UploadScript with sudo
	err := container.Container.CreateDeckhouseDirs()
	require.NoError(t, err, "could not create deckhouse dirs")

	containerPort := container.LocalPort()
	localServerPort := sshtesting.RandPortExclude([]int{containerPort})

	const response = "Simple response"
	handler := sshtesting.NewSimpleHTTPHandler("/my/action", response)

	sshtesting.MustStartHTTPServer(t, test, localServerPort, handler)

	registerStopReverceTunnel := func(t *testing.T, tunnel *ReverseTunnel) {
		t.Cleanup(func() {
			tunnel.Stop()
		})
	}

	containerSSHDPort := container.Container.RemotePort()
	upTunnelRemoteServerPort := sshtesting.RandPortExclude([]int{containerSSHDPort})

	t.Run("Reverse tunnel from container to host", func(t *testing.T) {
		remoteServerInvalidPort := sshtesting.RandPortExclude([]int{upTunnelRemoteServerPort, containerSSHDPort})
		localInvalidPort := sshtesting.RandInvalidPortExclude([]int{localServerPort})

		cases := []struct {
			title       string
			address     string
			wantErr     bool
			err         string
			errFromChan string
		}{
			{
				title:   "Tunnel, success",
				address: tunnelAddressString(localServerPort, upTunnelRemoteServerPort),
				wantErr: false,
			},
			{
				title:   "Invalid address",
				address: "swsws:111aaa:",
				wantErr: true,
				err:     "invalid address must be 'remote_bind:remote_port:local_bind:local_port'",
			},
			{
				title:   "Invalid local bind",
				address: tunnelAddressString(localInvalidPort, containerSSHDPort),
				wantErr: true,
				err:     fmt.Sprintf("failed to listen remote on 127.0.0.1:%d", upTunnelRemoteServerPort),
			},
			{
				title:       "Wrong local bind",
				address:     tunnelAddressString(localServerPort, remoteServerInvalidPort),
				wantErr:     false,
				errFromChan: fmt.Sprintf("Cannot dial to 127.0.0.1:%d", remoteServerInvalidPort),
			},
		}

		for _, c := range cases {
			t.Run(c.title, func(t *testing.T) {
				tun := NewReverseTunnel(sshClient, c.address)
				err := tun.Up()

				registerStopReverceTunnel(t, tun)

				if c.wantErr {
					require.Error(t, err)
					require.Contains(t, err.Error(), c.err)
				}

				requestAddress := fmt.Sprintf("http://127.0.0.1:%d%s", upTunnelRemoteServerPort, handler.Path)

				// try to get a response from local web server
				cmd := NewSSHCommand(sshClient, "curl", "-m", "4", "-s", requestAddress)
				cmd.WithTimeout(6 * time.Second)
				out, err := cmd.CombinedOutput(context.Background())
				require.NoError(t, err, "execute remote curl %s", requestAddress)

				if len(c.errFromChan) == 0 {
					require.Equal(t, response, string(out))
				} else {
					errMsg := <-tun.errorCh
					require.Contains(t, errMsg.err.Error(), c.errFromChan)
				}

				// try to up again: expecting error
				err = tun.Up()
				require.Error(t, err)
				require.Equal(t, err.Error(), "already up")
			})
		}
	})

	t.Run("HealthMonitor test", func(t *testing.T) {
		healthMonitorRemoteServerPort := sshtesting.RandPortExclude([]int{upTunnelRemoteServerPort, containerSSHDPort})

		tun := NewReverseTunnel(sshClient, tunnelAddressString(localServerPort, healthMonitorRemoteServerPort))
		err := tun.Up()
		require.NoError(t, err)

		registerStopReverceTunnel(t, tun)

		remoteHealthz := fmt.Sprintf("http://127.0.0.1:%d%s", healthMonitorRemoteServerPort, sshtesting.HealthzPath)

		script := fmt.Sprintf(`#!/bin/bash
URL="%s"

curl -m 4 -s $URL > /dev/null
exit $?
`, remoteHealthz)

		testFile := test.MustCreateTmpFile(t, script, true, "script", "test.sh")

		checker := utils.NewRunScriptReverseTunnelChecker(sshClient, testFile)
		killer := utils.EmptyReverseTunnelKiller{}

		checkLoop := retry.NewEmptyParams(
			retry.WithName("Check tunnel"),
			retry.WithAttempts(30),
			retry.WithWait(2*time.Second),
			retry.WithLogger(test.Logger),
		)

		checkTunnelAction := func() error {
			out, err := checker.CheckTunnel(context.Background())
			if err != nil {
				test.Logger.InfoF("Failed to check tunnel: %s %v", out, err)
				return err
			}
			return nil
		}

		err = retry.NewLoopWithParams(checkLoop).Run(checkTunnelAction)
		require.NoError(t, err, "tunnel check")

		sshClient.WithLoopsParams(ClientLoopsParams{
			CheckReverseTunnel: retry.NewEmptyParams(
				retry.WithAttempts(5),
				retry.WithWait(500*time.Millisecond),
			),
		})

		upMonitorSleep := 2 * time.Second
		restartSleep := 5 * time.Second

		tun.StartHealthMonitor(context.Background(), checker, killer)
		test.Logger.InfoF(
			"Waiting %s for tunnel monitor to start. And restart container. Wait %s before start container for fail check",
			upMonitorSleep.String(),
			restartSleep.String(),
		)

		time.Sleep(upMonitorSleep)
		err = container.Container.Restart(true, restartSleep)
		require.NoError(t, err, "container restart")
		err = container.Container.CreateDeckhouseDirs()
		require.NoError(t, err, "create deckhouse dirs")

		test.Logger.InfoF(
			"Waiting %s for tunnel monitor to restart",
			upMonitorSleep.String(),
		)

		time.Sleep(upMonitorSleep)

		checkLoopAfterRestart := retry.SafeCloneOrNewParams(checkLoop).
			WithName("Check tunnel after restart")

		err = retry.NewLoopWithParams(checkLoopAfterRestart).Run(checkTunnelAction)
		require.NoError(t, err, "tunnel check after restart")

		test.Logger.InfoF(
			"Disconnect (fail connection between server and client) case. Wait %s before connect. Wait %s before check",
			restartSleep.String(),
			upMonitorSleep.String(),
		)

		// fail connection case
		err = container.Container.FailAndUpConnection(restartSleep)
		require.NoError(t, err, "container fail connection")

		time.Sleep(upMonitorSleep)

		checkLoopAfterDisconnect := retry.SafeCloneOrNewParams(checkLoop).
			WithName("Check tunnel after disconnect")

		err = retry.NewLoopWithParams(checkLoopAfterDisconnect).Run(checkTunnelAction)
		require.NoError(t, err, "tunnel check after disconnect")
	})
}
