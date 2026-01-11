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
	"log/slog"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/log"
	"github.com/deckhouse/lib-dhctl/pkg/retry"
	gossh "github.com/deckhouse/lib-gossh"
	"github.com/deckhouse/lib-gossh/agent"
	"github.com/name212/govalue"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
	"github.com/deckhouse/lib-connection/pkg/ssh/utils"
)

func NewClient(ctx context.Context, sett settings.Settings, session *session.Session, privKeys []session.AgentPrivateKey) *Client {
	return &Client{
		SessionSettings: session,
		privateKeys:     privKeys,
		live:            false,
		sessionList:     make([]*gossh.Session, 5),
		ctx:             ctx,
		silent:          false,
		settings:        sett,
	}
}

type ClientLoopsParams struct {
	ConnectToBastion        retry.Params
	ConnectToHostViaBastion retry.Params
	ConnectToHostDirectly   retry.Params
	NewSession              retry.Params
	CheckReverseTunnel      retry.Params
}

var defaultClientDirectlyLoopParamsOps = []retry.ParamsBuilderOpt{
	retry.WithWait(2 * time.Second),
	retry.WithAttempts(50),
}

var defaultClientViaBastionLoopParamsOps = []retry.ParamsBuilderOpt{
	retry.WithWait(5 * time.Second),
	retry.WithAttempts(30),
}

var defaultSessionLoopParamsOps = []retry.ParamsBuilderOpt{
	retry.WithWait(5 * time.Second),
	retry.WithAttempts(10),
}

var defaultReverseTunnelParamsOps = []retry.ParamsBuilderOpt{
	retry.WithWait(2 * time.Second),
	retry.WithAttempts(2),
}

type Client struct {
	settings    settings.Settings
	loopsParams ClientLoopsParams

	sshClient *gossh.Client

	SessionSettings *session.Session

	privateKeys []session.AgentPrivateKey

	SSHConn       *gossh.Conn
	NetConn       *net.Conn
	BastionClient *gossh.Client

	stopChan chan struct{}
	live     bool

	kubeProxies []*KubeProxy
	sessionList []*gossh.Session

	signers []gossh.Signer

	ctx          context.Context
	sessionMutex sync.Mutex

	silent bool
}

func (s *Client) WithLoopsParams(p ClientLoopsParams) *Client {
	s.loopsParams = p
	return s
}

func (s *Client) initSigners() error {
	if len(s.signers) > 0 {
		s.settings.Logger().DebugLn("Signers already initialized")
		return nil
	}

	signers := make([]gossh.Signer, 0, len(s.privateKeys))
	for _, keypath := range s.privateKeys {
		key, err := utils.GetSSHPrivateKey(keypath.Key, keypath.Passphrase)
		if err != nil {
			return err
		}
		signer, err := gossh.NewSignerFromKey(key)
		if err != nil {
			return fmt.Errorf("Unable to parse private key: %v", err)
		}
		signers = append(signers, signer)
	}

	s.signers = signers
	return nil
}

func (s *Client) OnlyPreparePrivateKeys() error {
	return s.initSigners()
}

func (s *Client) Start() error {
	return s.startWithContext(s.ctx)
}

func (s *Client) startWithContext(ctx context.Context) error {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}

	logger := s.settings.Logger()

	if s.SessionSettings == nil {
		return fmt.Errorf("possible bug in ssh client: session should be created before start")
	}

	logger.DebugLn("Starting go ssh client....")

	if err := s.initSigners(); err != nil {
		return err
	}

	var agentClient agent.ExtendedAgent
	socket := s.settings.AuthSock()
	if socket != "" {
		logger.DebugF("Dialing SSH agent unix socket %s ...", socket)
		socketConn, err := net.Dial("unix", socket)
		if err != nil {
			return fmt.Errorf("Failed to open SSH_AUTH_SOCK: %v", err)
		}
		agentClient = agent.NewClient(socketConn)
	}

	var bastionClient *gossh.Client
	var client *gossh.Client
	if s.SessionSettings.BastionHost != "" {
		bastionConfig := &gossh.ClientConfig{}
		logger.DebugLn("Initialize bastion connection...")

		authMethods, err := s.authMethods(agentClient, s.SessionSettings.BastionPassword)
		if err != nil {
			return err
		}

		bastionConfig = &gossh.ClientConfig{
			User:            s.SessionSettings.BastionUser,
			Auth:            authMethods,
			HostKeyCallback: gossh.InsecureIgnoreHostKey(),
			Timeout:         3 * time.Second,
		}
		bastionAddr := fmt.Sprintf("%s:%s", s.SessionSettings.BastionHost, s.SessionSettings.BastionPort)
		fullHost := fmt.Sprintf("bastion host '%s' with user '%s'", bastionAddr, s.SessionSettings.BastionUser)
		connectToBastion := func() error {
			logger.DebugF("Connect to %s", fullHost)

			var err error
			bastionClient, err = s.DialTimeout(ctx, "tcp", bastionAddr, bastionConfig)

			return err
		}

		bastionLoopParams := retry.SafeCloneOrNewParams(s.loopsParams.ConnectToBastion, defaultClientViaBastionLoopParamsOps...).
			WithName("Get bastion SSH client").
			WithLogger(logger)

		if err := s.runInLoop(ctx, bastionLoopParams, connectToBastion); err != nil {
			return fmt.Errorf("Could not connect to %s", fullHost)
		}

		logger.DebugF("Connected successfully to bastion host %s\n", bastionAddr)
	}

	authMethods, err := s.authMethods(agentClient, s.SessionSettings.BecomePass)
	if err != nil {
		return err
	}

	logger.DebugF("Initial ssh privater keys auth to master host")

	config := &gossh.ClientConfig{
		User:            s.SessionSettings.User,
		Auth:            authMethods,
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	var targetConn net.Conn
	var clientConn gossh.Conn

	config.BannerCallback = func(message string) error {
		return nil
	}

	if bastionClient == nil {
		logger.DebugLn("Try to direct connect host master host")

		connectToHost := func() error {
			if len(s.kubeProxies) == 0 {
				s.SessionSettings.ChoiceNewHost()
			}

			addr := fmt.Sprintf("%s:%s", s.SessionSettings.Host(), s.SessionSettings.Port)
			logger.DebugF("Connect to master host '%s' with user '%s'\n", addr, s.SessionSettings.User)

			var err error
			client, err = s.DialTimeout(ctx, "tcp", addr, config)

			return err
		}

		hostLoopParams := retry.SafeCloneOrNewParams(s.loopsParams.ConnectToHostDirectly, defaultClientDirectlyLoopParamsOps...).
			WithName("Get SSH client").
			WithLogger(logger)

		if err := s.runInLoop(ctx, hostLoopParams, connectToHost); err != nil {
			lastHost := fmt.Sprintf("'%s:%s' with user '%s'", s.SessionSettings.Host(), s.SessionSettings.Port, s.SessionSettings.User)
			return fmt.Errorf("Failed to connect to master host (last %s): %w", lastHost, err)
		}

		s.sshClient = client
		s.live = true

		if s.stopChan == nil {
			stopCh := make(chan struct{})
			s.stopChan = stopCh
			go s.keepAlive()
		}

		return nil
	}

	logger.DebugF("Try to connect to through bastion host master host")

	var (
		addr             string
		targetClientConn gossh.Conn
		targetNewChan    <-chan gossh.NewChannel
		targetReqChan    <-chan *gossh.Request
	)

	connectToTarget := func() error {
		if len(s.kubeProxies) == 0 {
			s.SessionSettings.ChoiceNewHost()
		}
		addr = fmt.Sprintf("%s:%s", s.SessionSettings.Host(), s.SessionSettings.Port)
		logger.DebugF("Connect to target host '%s' with user '%s' through bastion host\n", addr, s.SessionSettings.User)

		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		targetConn, err = bastionClient.DialContext(cctx, "tcp", addr)
		if err != nil {
			return err
		}
		if s.settings.IsDebug() {
			targetClientConn, targetNewChan, targetReqChan, err = gossh.NewClientConnWithDebug(targetConn, addr, config, getSSHLogger(s.settings))
		} else {
			targetClientConn, targetNewChan, targetReqChan, err = gossh.NewClientConn(targetConn, addr, config)
		}

		return err
	}

	viaBastionLoopParams := retry.SafeCloneOrNewParams(s.loopsParams.ConnectToHostViaBastion, defaultClientViaBastionLoopParamsOps...).
		WithName("Get SSH client and connect to target host").
		WithLogger(logger)

	if err := s.runInLoop(ctx, viaBastionLoopParams, connectToTarget); err != nil {
		lastHost := fmt.Sprintf("'%s:%s' with user '%s'", s.SessionSettings.Host(), s.SessionSettings.Port, s.SessionSettings.User)
		return fmt.Errorf("Failed to connect to target host through bastion host (last %s): %w", lastHost, err)
	}

	clientConn = targetClientConn
	client = gossh.NewClient(targetClientConn, targetNewChan, targetReqChan)

	s.sshClient = client
	s.BastionClient = bastionClient
	s.NetConn = &targetConn
	s.SSHConn = &clientConn
	s.live = true

	if s.stopChan == nil {
		stopCh := make(chan struct{})
		s.stopChan = stopCh
		go s.keepAlive()
	}

	return nil
}

func (s *Client) authMethods(agentClient agent.ExtendedAgent, password string) ([]gossh.AuthMethod, error) {
	logger := s.settings.Logger()

	var authMethods []gossh.AuthMethod
	if len(s.signers) > 0 {
		logger.DebugF("Adding private key method")
		authMethods = append(authMethods, gossh.PublicKeys(s.signers...))
	}

	if !govalue.Nil(agentClient) {
		logger.DebugF("Adding agent socket to auth method")
		authMethods = append(authMethods, gossh.PublicKeysCallback(agentClient.Signers))
	}

	if password != "" {
		logger.DebugF("Initial password auth to master host")
		authMethods = append(authMethods, gossh.Password(password))
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("Private keys or SSH_AUTH_SOCK environment variable or become password should passed")
	}

	return authMethods, nil
}

func (s *Client) runInLoop(ctx context.Context, params retry.Params, task func() error) error {
	createLoop := retry.NewLoopWithParams
	if s.silent {
		createLoop = retry.NewSilentLoopWithParams
	}

	return createLoop(params).RunContext(ctx, task)
}

func (s *Client) keepAlive() {
	logger := s.settings.Logger()
	defer logger.DebugLn("keep-alive goroutine stopped")
	errorsCount := 0

	sleep := time.Second * 5

	for {
		select {
		case <-s.stopChan:
			logger.DebugLn("Stopping keep-alive goroutine.")
			close(s.stopChan)
			s.stopChan = nil
			return
		default:
			session, err := s.sshClient.NewSession()
			if err != nil {
				logger.DebugF("Keep-alive to %s failed: %v", s.SessionSettings.Host(), err)
				if errorsCount > 3 {
					s.restart()
					return
				}
				errorsCount++
				logger.DebugF("Keep-alive to %s failed: %v. Sleep %s before next attempt", s.SessionSettings.Host(), err, sleep.String())
				time.Sleep(sleep)
				continue
			}
			if _, err := session.SendRequest("keepalive@openssh.com", false, nil); err != nil {
				logger.DebugF("Keep-alive failed: %v", err)
				if errorsCount > 3 {
					s.restart()
					return
				}
				errorsCount++
			}
			if err := session.Close(); err != nil {
				logger.DebugF("Keep-alive session close failed: %v", err)
			}
			for _, sess := range s.sessionList {
				if sess != nil {
					if _, err := sess.SendRequest("keepalive@openssh.com", false, nil); err != nil {
						logger.DebugF("Keep-alive for session failed: %v\n", err)
					}
				} else {
					s.UnregisterSession(sess)
				}

			}
			logger.DebugF("Keep-alive to %s. Sleep %s before next request", s.SessionSettings.Host(), err, sleep.String())
			time.Sleep(sleep)
		}
	}
}

func (s *Client) restart() {
	s.live = false
	s.stopChan = nil
	s.silent = true
	s.Start()
	s.sessionList = nil
}

func (s *Client) DialTimeout(ctx context.Context, network, addr string, config *gossh.ClientConfig) (*gossh.Client, error) {
	d := net.Dialer{Timeout: config.Timeout}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		conn.Close()
		return nil, err
	}

	err = tcpConn.SetKeepAlive(true)
	if err != nil {
		tcpConn.Close()
		return nil, err
	}

	timeFactor := time.Duration(3)
	err = tcpConn.SetDeadline(time.Now().Add(config.Timeout * timeFactor))
	if err != nil {
		tcpConn.Close()
		return nil, err
	}

	var (
		c     gossh.Conn
		chans <-chan gossh.NewChannel
		reqs  <-chan *gossh.Request
	)

	if s.settings.IsDebug() {
		c, chans, reqs, err = gossh.NewClientConnWithDebug(tcpConn, addr, config, getSSHLogger(s.settings))
	} else {
		c, chans, reqs, err = gossh.NewClientConn(tcpConn, addr, config)
	}
	if err != nil {
		return nil, err
	}

	err = tcpConn.SetDeadline(time.Time{})
	if err != nil {
		tcpConn.Close()
		return nil, err
	}

	return gossh.NewClient(c, chans, reqs), nil
}

// Tunnel is used to open local (L) and remote (R) tunnels
func (s *Client) Tunnel(address string) connection.Tunnel {
	return NewTunnel(s, address)
}

// ReverseTunnel is used to open remote (R) tunnel
func (s *Client) ReverseTunnel(address string) connection.ReverseTunnel {
	return NewReverseTunnel(s, address)
}

// Command is used to run commands on remote server
func (s *Client) Command(name string, arg ...string) connection.Command {
	return NewSSHCommand(s, name, arg...)
}

// KubeProxy is used to start kubectl proxy and create a tunnel from local port to proxy port
func (s *Client) KubeProxy() connection.KubeProxy {
	p := NewKubeProxy(s, s.SessionSettings)
	s.kubeProxies = append(s.kubeProxies, p)
	return p
}

// File is used to upload and download files and directories
func (s *Client) File() connection.File {
	return NewSSHFile(s.settings, s.sshClient)
}

// UploadScript is used to upload script and execute it on remote server
func (s *Client) UploadScript(scriptPath string, args ...string) connection.Script {
	return NewSSHUploadScript(s, scriptPath, args...)
}

// Check is used to upload script and execute it on remote server
func (s *Client) Check() connection.Check {
	f := func(sess *session.Session, cmd string) connection.Command {
		return NewSSHCommand(s, cmd)
	}
	return utils.NewCheck(f, s.SessionSettings, s.settings)
}

// Stop the client
func (s *Client) Stop() {
	logger := s.settings.Logger()

	if s.sshClient == nil {
		logger.DebugLn("no SSH client found to stop. Exiting...")
		return
	}
	logger.DebugLn("SSH Client is stopping now")
	logger.DebugLn("stopping kube proxies")
	for _, p := range s.kubeProxies {
		p.StopAll()
	}
	s.kubeProxies = nil

	logger.DebugLn("closing sessions")
	for _, sess := range s.sessionList {
		if sess != nil {
			sess.Signal(gossh.SIGKILL)
			sess.Close()
		}
	}
	s.sessionList = nil

	// by starting kubeproxy on remote, there is one more process starts
	// it cannot be killed by sending any signal to his parrent process
	// so we need to use killall command to kill all this processes
	logger.DebugLn("stopping kube proxies on remote")
	s.stopKubeproxy()
	logger.DebugLn("kube proxies on remote were stopped")

	logger.DebugLn("stopping keep-alive goroutine")
	if s.stopChan != nil {
		logger.DebugLn("sendind message to stop keep-alive")
		s.stopChan <- struct{}{}
	}

	s.sshClient.Close()
	if s.SSHConn != nil {
		sshconn := *s.SSHConn
		sshconn.Close()
	}
	if s.NetConn != nil {
		netconn := *s.NetConn
		netconn.Close()
	}
	if s.BastionClient != nil {
		s.BastionClient.Close()
	}
	logger.DebugLn("SSH Client is stopped")
}

func (s *Client) Session() *session.Session {
	return s.SessionSettings
}

func (s *Client) PrivateKeys() []session.AgentPrivateKey {
	return s.privateKeys
}

func (s *Client) RefreshPrivateKeys() error {
	// new go ssh client already have all keys
	return nil
}

// Loop Looping all available hosts
func (s *Client) Loop(fn connection.SSHLoopHandler) error {
	var err error

	resetSession := func() {
		s.SessionSettings = s.SessionSettings.Copy()
		s.SessionSettings.ChoiceNewHost()
	}
	defer resetSession()
	resetSession()

	for range s.SessionSettings.AvailableHosts() {
		err = fn(s)
		if err != nil {
			return err
		}
		s.SessionSettings.ChoiceNewHost()
	}

	return nil
}

func (s *Client) NewSession() (*gossh.Session, error) {
	var sess *gossh.Session

	newSessionLoopParams := retry.SafeCloneOrNewParams(s.loopsParams.NewSession, defaultSessionLoopParamsOps...).
		WithName("Establish new session").
		WithLogger(s.settings.Logger())

	err := retry.NewSilentLoopWithParams(newSessionLoopParams).RunContext(s.ctx, func() error {
		var err error
		sess, err = s.sshClient.NewSession()
		return err
	})

	if err != nil {
		return nil, err
	}

	s.RegisterSession(sess)
	return sess, nil
}

func (s *Client) GetClient() *gossh.Client {
	return s.sshClient
}

func (s *Client) Live() bool {
	return s.live
}

func (s *Client) RegisterSession(sess *gossh.Session) {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()
	s.sessionList = append(s.sessionList, sess)
}

func (s *Client) UnregisterSession(sess *gossh.Session) {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()
	num := len(s.sessionList)
	for i, s := range s.sessionList {
		if s == sess {
			num = i
			break
		}
	}
	if num < len(s.sessionList) {
		s.sessionList = slices.Delete(s.sessionList, num, num+1)
	}
}

func (s *Client) stopKubeproxy() {
	cmd := NewSSHCommand(s, "killall kubectl")
	cmd.Sudo(context.Background())
	cmd.Run(context.Background())
}

func getSSHLogger(sett settings.Settings) *slog.Logger {
	return log.NewSLogWithPrefixAndDebug(context.TODO(), sett.LoggerProvider(), "ssh", true)
}
