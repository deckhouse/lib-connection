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

package kubeproxy

import (
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/name212/govalue"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
)

type StartCommandParams struct {
	OnStart       func()
	StdoutHandler func(string)
	WaitHandler   func(err error)
	Cmd           string
}

type Runner interface {
	StartCommand(params StartCommandParams) (connection.KubeProxyCommand, error)
	UpTunnel(address string) (connection.Tunnel, error)
}

type BaseKubeProxy struct {
	session *session.Session
	sett    settings.Settings

	runner Runner

	KubeProxyPort string
	LocalPort     string

	proxyMutex sync.RWMutex
	proxy      connection.KubeProxyCommand

	tunnelMu sync.RWMutex
	tunnel   connection.Tunnel

	stop      bool
	port      string
	localPort int

	monitorsMu              sync.Mutex
	healthMonitorsByStartID map[int]chan struct{}
}

func NewBaseKubeProxy(runner Runner, sett settings.Settings, sess *session.Session) *BaseKubeProxy {
	return &BaseKubeProxy{
		runner:                  runner,
		sett:                    sett,
		session:                 sess,
		port:                    "0",
		localPort:               DefaultLocalAPIPort,
		healthMonitorsByStartID: make(map[int]chan struct{}),
	}
}

func (k *BaseKubeProxy) Start(useLocalPort int) (string, error) {
	startID := rand.Int()

	k.debugWithID(startID, "Call start Kube-proxy  port:%d", useLocalPort)

	success := false
	defer func() {
		k.stop = false
		if !success {
			k.debugWithID(startID, "Kube-proxy was not started. Try to clear all")
			k.Stop(startID)
		}
		k.debugWithID(startID, "Kube-proxy starting on %d was finished", k.localPort)
	}()

	proxyCommandErrorCh := make(chan error, 1)
	var proxy connection.KubeProxyCommand
	var port string
	var err error
	for {
		proxy, port, err = k.runKubeProxy(proxyCommandErrorCh, startID)
		if err != nil {
			k.debugWithID(startID, "Got error from runKubeProxy func: %v", err)
			return "", err
		}

		k.stop = false
		portNum, err := strconv.Atoi(port)
		if err != nil {
			continue
		}
		if portNum > 1024 {
			break
		}
		k.debugWithID(startID, "Proxy run on privileged port %s and will be stopped and restarted", port)
		k.Stop(startID)
	}

	k.debugWithID(startID, "Proxy was started successfully")

	k.setProxy(proxy)
	k.port = port

	tunnelErrorCh := make(chan error)
	tun, localPort, lastError := k.upTunnel(port, useLocalPort, tunnelErrorCh, startID)
	if lastError != nil {
		k.debugWithID(startID, "Got error from upTunnel func: %v", err)
		return "", fmt.Errorf("tunnel up error: max retries reached, last error: %w", lastError)
	}

	k.setTunnel(tun)
	k.localPort = localPort

	monitorCh := k.createMonitorCh(startID)
	go k.healthMonitor(
		proxyCommandErrorCh,
		tunnelErrorCh,
		monitorCh,
		startID,
	)

	success = true

	return fmt.Sprintf("%d", k.localPort), nil
}

func (k *BaseKubeProxy) StopAll() {
	k.Stop(-1)
}

func (k *BaseKubeProxy) Stop(startID int) {
	if k == nil {
		return
	}

	if k.stop {
		k.debugWithID(startID, "Stop kube-proxy: kube proxy already stopped. Skip")
		return
	}

	if startID < 1 {
		for id := range k.healthMonitorsByStartID {
			k.stopHealthMonitor(id)
		}
	} else {
		k.stopHealthMonitor(startID)
	}

	proxy, err := k.getProxy()
	if err == nil {
		k.debugWithID(startID, "Stop proxy command")
		proxy.Stop()
		k.debugWithID(startID, "Proxy command stopped")
		k.setProxy(nil)
		k.port = "0"
	}

	tun, err := k.getTunnel()
	if err == nil {
		k.debugWithID(startID, "Stop tunnel")
		tun.Stop()
		k.debugWithID(startID, "Tunnel stopped")
		k.setTunnel(nil)
	}

	k.stop = true
}

func (k *BaseKubeProxy) stopHealthMonitor(startID int) {
	k.monitorsMu.Lock()
	defer k.monitorsMu.Unlock()

	ch, ok := k.healthMonitorsByStartID[startID]
	if !ok || ch == nil {
		return
	}

	ch <- struct{}{}
	delete(k.healthMonitorsByStartID, startID)
}

func (k *BaseKubeProxy) createMonitorCh(startID int) chan struct{} {
	k.monitorsMu.Lock()
	defer k.monitorsMu.Unlock()

	c := make(chan struct{}, 1)
	k.healthMonitorsByStartID[startID] = c

	return c
}

func (k *BaseKubeProxy) tryToRestartFully(startID int) {
	k.debugWithID(startID, "Try restart kube proxy fully")
	sleep := 4 * time.Second

	for {
		k.Stop(startID)

		_, err := k.Start(k.localPort)

		if err == nil {
			k.stop = false
			k.debugWithID(startID, "Proxy was restarted successfully")
			return
		}

		// need warn for human
		k.sett.Logger().WarnF(
			"[%d] Proxy was not restarted: %v. Sleep %s seconds before next attempt",
			startID,
			err,
			sleep.String(),
		)

		time.Sleep(sleep)

		k.session.ChoiceNewHost()
		k.debugWithID(startID, "New host selected on fully restart %s", k.session.Host())
	}
}

func (k *BaseKubeProxy) healthMonitor(
	proxyErrorCh, tunnelErrorCh chan error,
	stopCh chan struct{},
	startID int,
) {
	k.debugWithID(startID, "Kube proxy health monitor started")
	defer k.debugWithID(startID, "Kube proxy health monitor stopped")

	proxyErrorCount := 0
	for {
		k.debugWithID(startID, "Kube proxy monitor step")
		select {
		case err := <-proxyErrorCh:
			k.debugWithID(startID, "Proxy failed with error %v", err)
			// if proxy crushed, we need to restart kube-proxy fully
			// with proxy and tunnel (tunnel depends on proxy)
			k.tryToRestartFully(startID)
			// if we restart proxy fully
			// this monitor must be finished because new monitor was started
			return

		case err := <-tunnelErrorCh:
			k.debugWithID(startID, "Tunnel failed. Stopping previous tunnel: %v", err)
			// we need fully stop tunnel because
			tun, err := k.getTunnel()
			if err == nil {
				tun.Stop()
			}

			k.debugWithID(startID, "Tunnel stopped before restart. Starting new tunnel...")

			if proxyErrorCount < 3 {
				var err error
				tun, _, err := k.upTunnel(k.port, k.localPort, tunnelErrorCh, startID)
				if err != nil {
					k.debugWithID(startID, "Tunnel was not up: %v. Try to restart fully", err)
					k.tryToRestartFully(startID)
					return
				} else {
					k.setTunnel(tun)
				}

				proxyErrorCount++
			} else {
				k.tryToRestartFully(startID)
				return
			}

			k.debugWithID(startID, "Tunnel re up successfully")

		case <-stopCh:
			k.debugWithID(startID, "Got kube proxy stopped message")
			return
		}
	}
}

func (k *BaseKubeProxy) upTunnel(
	kubeProxyPort string,
	useLocalPort int,
	tunnelErrorCh chan error,
	startID int,
) (connection.Tunnel, int, error) {
	k.debugWithID(startID,
		"Starting up tunnel with proxy port %s and local port %d",
		kubeProxyPort,
		useLocalPort,
	)

	rewriteLocalPort := false
	localPort := useLocalPort

	portProvider := NewPortProvider(useLocalPort)

	if useLocalPort < 1 {
		k.debugWithID(startID,
			"Incorrect local port %d use default %d",
			startID,
			useLocalPort,
			DefaultLocalAPIPort,
		)
		localPort = portProvider.Next()
		rewriteLocalPort = true
	}

	maxRetries := 5
	retries := 0
	var lastError error
	var tun connection.Tunnel
	for {
		k.debugWithID(startID, "Start %d iteration for up tunnel on %d", retries, localPort)
		proxy, getProxyErr := k.getProxy()
		if getProxyErr != nil {
			return nil, 0, fmt.Errorf("failed to get proxy proxy is: %v", getProxyErr)
		}

		if proxy.WaitError() != nil {
			lastError = fmt.Errorf("proxy was failed while restart tunnel")
			break
		}

		// try to start tunnel from localPort to proxy port
		var tunnelAddress string
		if v := os.Getenv("KUBE_PROXY_BIND_ADDR"); v != "" {
			tunnelAddress = fmt.Sprintf("%s:%d:localhost:%s", v, localPort, kubeProxyPort)
		} else {
			tunnelAddress = fmt.Sprintf("%s:%s:localhost:%d", "127.0.0.1", kubeProxyPort, localPort)
		}

		k.debugWithID(startID, "Try up tunnel on %s", tunnelAddress)
		newTun, upTunnelErr := k.runner.UpTunnel(tunnelAddress)
		if upTunnelErr != nil {
			k.debugWithID(startID, "Start tunnel was failed. Cleaning...")

			if !govalue.Nil(tun) {
				tun.Stop()
			}

			lastError = fmt.Errorf("tunnel '%s': %w", tunnelAddress, upTunnelErr)
			k.debugWithID(startID, "Start tunnel was failed. Error: %v", lastError)

			if rewriteLocalPort {
				localPort = portProvider.Next()
				k.debugWithID(startID, "New local port %d", localPort)
			}

			retries++
			if retries >= maxRetries {
				k.debugWithID(startID, "Last iteration finished")
				tun = nil
				break
			}
		} else {
			k.debugWithID(startID, "Tunnel was started. Starting health monitor")
			go newTun.HealthMonitor(tunnelErrorCh)
			lastError = nil
			tun = newTun
			break
		}
	}

	dbgMsg := fmt.Sprintf("Tunnel up on local port %d", localPort)
	if lastError != nil {
		dbgMsg = fmt.Sprintf("Tunnel was not up: %v", lastError)
	}

	k.debugWithID(startID, "%s", dbgMsg)

	return tun, localPort, lastError
}

var portRe = regexp.MustCompile(`Starting to serve on .*?:(\d+)`)

func (k *BaseKubeProxy) runKubeProxy(
	waitCh chan error,
	startID int,
) (connection.KubeProxyCommand, string, error) {
	k.debugWithID(startID, "Begin starting proxy")

	cmd := k.proxyCMD(startID)

	port := ""
	portReady := make(chan struct{}, 1)

	stdOutHandler := func(line string) {
		m := portRe.FindStringSubmatch(line)
		if len(m) == 2 && m[1] != "" {
			port = m[1]
			k.debugWithID(startID, "Got proxy port = %s on host %s", port, k.session.Host())
			portReady <- struct{}{}
		}
	}

	onStart := make(chan struct{}, 1)

	onStartHandler := func() {
		k.debugWithID(startID, "Command started")
		onStart <- struct{}{}
	}

	waitHandler := func(err error) {
		k.debugWithID(startID, "Wait error: %v", err)
		waitCh <- err
	}

	k.debugWithID(startID, "Start proxy command")

	proxy, err := k.runner.StartCommand(StartCommandParams{
		OnStart:       onStartHandler,
		StdoutHandler: stdOutHandler,
		WaitHandler:   waitHandler,
		Cmd:           cmd,
	})

	if err != nil {
		k.debugWithID(startID, "Start proxy command error: %v", err)
		return nil, "", fmt.Errorf("start kubectl proxy: %w", err)
	}

	k.debugWithID(startID, "Proxy command was started")

	returnWaitErr := func(err error) error {
		k.debugWithID(startID, "Proxy command waiting error: %v", err)
		template := `Proxy exited suddenly: %s%s
Status: %w`
		return fmt.Errorf(template, string(proxy.StdoutBytes()), string(proxy.StderrBytes()), err)
	}

	// we need to check that kubeproxy was started
	// that checking wait string pattern in output
	// but we may receive error and this error will get from waitCh
	select {
	case <-onStart:
	case err := <-waitCh:
		return nil, "", returnWaitErr(err)
	}

	// Wait for proxy startup
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	select {
	case e := <-waitCh:
		return nil, "", returnWaitErr(e)
	case <-t.C:
		k.debugWithID(startID, "Starting proxy command timeout")
		return nil, "", fmt.Errorf("timeout waiting for api proxy port")
	case <-portReady:
		if port == "" {
			k.debugWithID(startID, "Starting proxy command: empty port")
			return nil, "", fmt.Errorf("got empty port from kubectl proxy")
		}
	}

	k.debugWithID(startID, "Proxy process started with port: %s", port)
	return proxy, port, nil
}

func (k *BaseKubeProxy) proxyCMD(startID int) string {
	kubectlProxy := fmt.Sprintf(
		// --disable-filter is needed to exec into etcd pods
		"kubectl proxy --as=dhctl --as-group=system:masters --port=%s --kubeconfig /etc/kubernetes/admin.conf --disable-filter",
		k.port,
	)
	if v := os.Getenv("KUBE_PROXY_ACCEPT_HOSTS"); v != "" {
		kubectlProxy += fmt.Sprintf(" --accept-hosts='%s'", v)
	}
	command := fmt.Sprintf("PATH=$PATH:%s/; %s", k.sett.NodeBinPath(), kubectlProxy)

	k.debugWithID(startID, "Proxy command for start: %s", command)

	return command
}

var errEmpty = fmt.Errorf("empty")

func (k *BaseKubeProxy) setProxy(c connection.KubeProxyCommand) {
	k.proxyMutex.Lock()
	defer k.proxyMutex.Unlock()

	k.proxy = c
}

func (k *BaseKubeProxy) getProxy() (connection.KubeProxyCommand, error) {
	k.proxyMutex.RLock()
	defer k.proxyMutex.RUnlock()

	c := k.proxy
	if govalue.Nil(c) {
		return nil, errEmpty
	}

	return c, nil
}

func (k *BaseKubeProxy) setTunnel(t connection.Tunnel) {
	k.tunnelMu.Lock()
	defer k.tunnelMu.Unlock()

	k.tunnel = t
}

func (k *BaseKubeProxy) getTunnel() (connection.Tunnel, error) {
	k.tunnelMu.RLock()
	defer k.tunnelMu.RUnlock()

	t := k.tunnel
	if govalue.Nil(t) {
		return nil, errEmpty
	}

	return t, nil
}

func (k *BaseKubeProxy) debugWithID(id int, f string, args ...any) {
	if id > 0 {
		f = "[%d] " + f
		args = append([]any{id}, args...)
	}

	k.sett.Logger().DebugF(f, args...)
}
