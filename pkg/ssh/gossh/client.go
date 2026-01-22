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
		sessionClient:   session,
		privateKeys:     privKeys,
		live:            false,
		sshSessionsList: make([]*gossh.Session, 0, 10),
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
	ctx context.Context

	settings    settings.Settings
	loopsParams ClientLoopsParams

	bastionClient *gossh.Client
	sshClient     *gossh.Client

	sessionClient *session.Session

	sshConn    gossh.Conn
	sshNetConn net.Conn
	stopChan   chan struct{}

	live        bool
	kubeProxies []*KubeProxy

	sshSessionsMu   sync.Mutex
	sshSessionsList []*gossh.Session

	privateKeys []session.AgentPrivateKey
	signers     []gossh.Signer

	agentClient     agent.ExtendedAgent
	agentConnection net.Conn

	silent  bool
	stopped bool
}

func (s *Client) WithLoopsParams(p ClientLoopsParams) *Client {
	s.loopsParams = p
	return s
}

func (s *Client) OnlyPreparePrivateKeys() error {
	return s.initSigners()
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
	p := NewKubeProxy(s, s.sessionClient)
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
	return utils.NewCheck(f, s.sessionClient, s.settings)
}

// Stop the client
func (s *Client) Stop() {
	s.stopAllAndLogErrors("call Stop()")
	s.stopped = true
	s.debug("SSH client is stopped")
}

func (s *Client) Session() *session.Session {
	return s.sessionClient
}

func (s *Client) Settings() settings.Settings {
	return s.settings
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
		s.sessionClient = s.sessionClient.Copy()
		s.sessionClient.ChoiceNewHost()
	}
	defer resetSession()
	resetSession()

	for range s.sessionClient.AvailableHosts() {
		err = fn(s)
		if err != nil {
			return err
		}
		s.sessionClient.ChoiceNewHost()
	}

	return nil
}

func (s *Client) NewSSHSession() (*gossh.Session, error) {
	var sess *gossh.Session

	newSessionLoopParams := retry.SafeCloneOrNewParams(s.loopsParams.NewSession, defaultSessionLoopParamsOps...).
		Clone(
			retry.WithName("Establish new session"),
			retry.WithLogger(s.settings.Logger()),
		)
	err := retry.NewSilentLoopWithParams(newSessionLoopParams).RunContext(s.ctx, func() error {
		var err error
		sess, err = s.sshClient.NewSession()
		return err
	})

	if err != nil {
		return nil, err
	}

	s.registerSession(sess)
	return sess, nil
}

func (s *Client) GetClient() *gossh.Client {
	return s.sshClient
}

func (s *Client) Live() bool {
	return s.live
}

func (s *Client) Start() error {
	return s.startWithContext(s.ctx)
}

func (s *Client) UnregisterSession(sess *gossh.Session) {
	s.sshSessionsMu.Lock()
	defer s.sshSessionsMu.Unlock()
	num := len(s.sshSessionsList)
	for i, registeredSession := range s.sshSessionsList {
		if registeredSession == sess {
			num = i
			break
		}
	}
	if num < len(s.sshSessionsList) {
		s.sshSessionsList = slices.Delete(s.sshSessionsList, num, num+1)
	}
}

func (s *Client) IsStopped() bool {
	return s.stopped
}

func (s *Client) stopAfterStartFailed(cause string, err error) error {
	s.stopAllAndLogErrors(cause)
	return err
}

func (s *Client) startWithContext(ctx context.Context) error {
	if s.sessionClient == nil {
		return fmt.Errorf("Possible bug in ssh client: client session should be passed start")
	}

	if govalue.Nil(ctx) {
		return fmt.Errorf("nil context passed to client")
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	s.debug("Starting go ssh client....")

	if err := s.initSigners(); err != nil {
		return err
	}

	if err := s.connectToAgent(ctx); err != nil {
		return s.stopAfterStartFailed("unable to connect to agent", err)
	}

	bastionClient, err := s.connectToBastion(ctx)
	if err != nil {
		return s.stopAfterStartFailed("unable to connect to bastion", err)
	}

	if err := s.connectToTarget(ctx, bastionClient); err != nil {
		return s.stopAfterStartFailed("unable to connect to target", err)
	}

	return nil
}

func (s *Client) connectToAgent(ctx context.Context) error {
	socket := s.settings.AuthSock()
	if socket == "" {
		s.debug("No auth socket passed. Skip connecting to agent")
		return nil
	}

	s.debug("Dialing SSH agent unix socket %s ...", socket)

	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Use net.Dialer's DialContext method directly
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(cctx, "unix", socket)
	if err != nil {
		return fmt.Errorf("Failed to open agent socket %s: %v", socket, err)
	}

	s.agentConnection = conn
	s.agentClient = agent.NewClient(conn)

	return nil
}

func (s *Client) createClientConfig(user string, password string, connectName string) (*gossh.ClientConfig, error) {
	authMethods, err := s.authMethods(password)
	if err != nil {
		return nil, err
	}

	config := &gossh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	config.BannerCallback = func(message string) error {
		s.debug("Got banner message for %s: %s", connectName, message)
		return nil
	}

	return config, nil
}

func (s *Client) createTargetClientConfig(connectName string) (*gossh.ClientConfig, error) {
	return s.createClientConfig(s.sessionClient.User, s.sessionClient.BecomePass, connectName)
}

func (s *Client) connectToTargetViaBastion(ctx context.Context, bastionClient *gossh.Client) (*gossh.Client, error) {
	if bastionClient == nil {
		return nil, fmt.Errorf("Bastion client is nil for connect via bastion")
	}

	var (
		addr             string
		targetConn       net.Conn
		targetClientConn gossh.Conn
	)

	s.debug("Try to connect to through bastion host master host...")

	config, err := s.createTargetClientConfig("connect via bastion")
	if err != nil {
		return nil, err
	}

	var sshConn *sshConnection

	connectToTarget := func() error {
		if len(s.kubeProxies) == 0 {
			s.sessionClient.ChoiceNewHost()
		}
		addr = fmt.Sprintf("%s:%s", s.sessionClient.Host(), s.sessionClient.Port)
		s.debug("Connect to target host '%s' with user '%s' through bastion host", addr, s.sessionClient.User)

		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		var err error
		targetConn, err = bastionClient.DialContext(cctx, "tcp", addr)
		if err != nil {
			return fmt.Errorf("Cannot Dial to %s over bastion: %w", addr, err)
		}

		sshConn, err = s.createSSHConnection(targetConn, addr, config)
		if err != nil {
			return fmt.Errorf("Cannot create SSH connection to %s: %w", addr, err)
		}

		return nil
	}

	viaBastionLoopParams := retry.SafeCloneOrNewParams(s.loopsParams.ConnectToHostViaBastion, defaultClientViaBastionLoopParamsOps...).
		Clone(
			retry.WithName("Get SSH client and connect to target host via bastion"),
		)

	if err := s.runInLoop(ctx, viaBastionLoopParams, connectToTarget); err != nil {
		lastHost := fmt.Sprintf("'%s:%s' with user '%s'", s.sessionClient.Host(), s.sessionClient.Port, s.sessionClient.User)
		return nil, fmt.Errorf("Failed to connect to target host through bastion host (last %s): %w", lastHost, err)
	}

	s.sshNetConn = targetConn
	s.sshConn = targetClientConn

	return sshConn.createGoClient(), nil
}

func (s *Client) connectToTarget(ctx context.Context, bastionClient *gossh.Client) error {
	var (
		client *gossh.Client
		err    error
	)

	if bastionClient == nil {
		client, err = s.directConnectToTarget(ctx)
	} else {
		client, err = s.connectToTargetViaBastion(ctx, bastionClient)
	}

	if err != nil {
		return err
	}

	s.sshClient = client
	s.bastionClient = bastionClient
	s.live = true

	if s.stopChan == nil {
		stopCh := make(chan struct{})
		s.stopChan = stopCh
	}

	go s.keepAlive()

	return nil
}

func (s *Client) directConnectToTarget(ctx context.Context) (*gossh.Client, error) {
	s.debug("Try to direct connect host master host...")

	config, err := s.createTargetClientConfig("direct connect")
	if err != nil {
		return nil, err
	}

	var client *gossh.Client

	connectToHost := func() error {
		if len(s.kubeProxies) == 0 {
			s.sessionClient.ChoiceNewHost()
		}

		addr := fmt.Sprintf("%s:%s", s.sessionClient.Host(), s.sessionClient.Port)
		s.debug("Connect to master host '%s' with user '%s'\n", addr, s.sessionClient.User)

		var err error
		client, err = s.dialContext(ctx, "tcp", addr, config)

		return err
	}

	hostLoopParams := retry.SafeCloneOrNewParams(s.loopsParams.ConnectToHostDirectly, defaultClientDirectlyLoopParamsOps...).
		Clone(retry.WithName("Get SSH client"))

	if err := s.runInLoop(ctx, hostLoopParams, connectToHost); err != nil {
		lastHost := fmt.Sprintf("'%s:%s' with user '%s'", s.sessionClient.Host(), s.sessionClient.Port, s.sessionClient.User)
		return nil, fmt.Errorf("Failed to connect to target directly (last %s): %w", lastHost, err)
	}

	return client, nil
}

func (s *Client) connectToBastion(ctx context.Context) (*gossh.Client, error) {
	if s.sessionClient.BastionHost == "" {
		s.debug("Bastion host is empty. Skip connection to bastion")
		return nil, nil
	}

	s.debug("Initialize bastion connection...")

	bastionUser := s.sessionClient.BastionUser

	bastionConfig, err := s.createClientConfig(bastionUser, s.sessionClient.BastionPassword, "bastion")
	if err != nil {
		return nil, err
	}

	var bastionClient *gossh.Client

	bastionAddr := fmt.Sprintf("%s:%s", s.sessionClient.BastionHost, s.sessionClient.BastionPort)
	fullHost := fmt.Sprintf("bastion host '%s' with user '%s'", bastionAddr, bastionUser)

	connectToBastion := func() error {
		s.debug("Connect to %s", fullHost)

		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		var err error
		bastionClient, err = s.dialContext(cctx, "tcp", bastionAddr, bastionConfig)

		return err
	}

	bastionLoopParams := retry.SafeCloneOrNewParams(s.loopsParams.ConnectToBastion, defaultClientViaBastionLoopParamsOps...).
		Clone(retry.WithName("Get bastion SSH client"))

	if err := s.runInLoop(ctx, bastionLoopParams, connectToBastion); err != nil {
		return nil, fmt.Errorf("Could not connect to %s: %w", fullHost, err)
	}

	s.debug("Connected successfully to bastion host %s", bastionAddr)

	return bastionClient, nil
}

func (s *Client) authMethods(password string) ([]gossh.AuthMethod, error) {
	var authMethods []gossh.AuthMethod
	if len(s.signers) > 0 {
		s.debug("Adding private key method")
		authMethods = append(authMethods, gossh.PublicKeys(s.signers...))
	}

	if !govalue.Nil(s.agentClient) {
		s.debug("Adding agent socket to auth method")
		authMethods = append(authMethods, gossh.PublicKeysCallback(s.agentClient.Signers))
	}

	if password != "" {
		s.debug("Initial password auth to master host")
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

	paramsWithLogger := params.Clone(retry.WithLogger(s.settings.Logger()))

	return createLoop(paramsWithLogger).RunContext(ctx, task)
}

func (s *Client) keepAlive() {
	defer s.debug("Keepalive goroutine stopped")

	checker := newKepAliveChecker(s, time.Second*5, 3)

	for {
		select {
		case <-s.stopChan:
			s.debug("Receive stop keepalive goroutine")
			close(s.stopChan)
			s.stopChan = nil
			return
		default:
			if err := checker.Check(); err != nil {
				// if check returns error we should restart client  exit from goroutine
				// all sleeps doing in to Check
				s.restart()
				return
			}
		}
	}
}

func (s *Client) restart() {
	s.live = false
	s.stopChan = nil
	s.silent = true
	if err := s.Start(); err != nil {
		s.debug("Start failed during restart: %v", err)
	}
	s.sshSessionsList = nil
}

type sshConnection struct {
	conn      gossh.Conn
	ch        <-chan gossh.NewChannel
	requestCh <-chan *gossh.Request
}

func (s *sshConnection) createGoClient() *gossh.Client {
	return gossh.NewClient(s.conn, s.ch, s.requestCh)
}

func (s *Client) createSSHConnection(c net.Conn, addr string, config *gossh.ClientConfig) (*sshConnection, error) {
	var (
		err       error
		conn      gossh.Conn
		ch        <-chan gossh.NewChannel
		requestCh <-chan *gossh.Request
	)

	if s.settings.IsDebug() {
		sshLogger := log.NewSLogWithPrefixAndDebug(
			context.TODO(),
			s.settings.LoggerProvider(),
			"go-ssh",
			true,
		)
		conn, ch, requestCh, err = gossh.NewClientConnWithDebug(c, addr, config, sshLogger)
	} else {
		conn, ch, requestCh, err = gossh.NewClientConn(c, addr, config)
	}

	if err != nil {
		return nil, err
	}

	return &sshConnection{
		conn:      conn,
		ch:        ch,
		requestCh: requestCh,
	}, nil
}

func (s *Client) dialContext(ctx context.Context, network, addr string, config *gossh.ClientConfig) (*gossh.Client, error) {
	closeConnectionAndReturnErr := func(msg string, err error, conn net.Conn) (*gossh.Client, error) {
		err = fmt.Errorf("Cannot Dial to '%s' %s: %w", addr, msg, err)

		if closeErr := utils.SafeClose(conn); closeErr != nil {
			err = fmt.Errorf("%w and cannot close connection %w", err, closeErr)
		}
		return nil, err
	}

	d := net.Dialer{Timeout: config.Timeout}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return closeConnectionAndReturnErr("connect", err, conn)
	}

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return closeConnectionAndReturnErr("is not tcp", err, conn)
	}

	err = tcpConn.SetKeepAlive(true)
	if err != nil {
		return closeConnectionAndReturnErr("cannot set keepalive", err, tcpConn)
	}

	timeFactor := time.Duration(3)
	deadline := time.Now().Add(config.Timeout * timeFactor)
	err = tcpConn.SetDeadline(deadline)
	if err != nil {
		return closeConnectionAndReturnErr(
			fmt.Sprintf("cannot set deadline %s", deadline.String()),
			err,
			tcpConn,
		)
	}

	sshConn, err := s.createSSHConnection(tcpConn, addr, config)
	if err != nil {
		return closeConnectionAndReturnErr("cannot create ssh connection", err, tcpConn)
	}

	err = tcpConn.SetDeadline(time.Time{})
	if err != nil {
		return closeConnectionAndReturnErr("cannot reset deadline", err, tcpConn)
	}

	return sshConn.createGoClient(), nil
}

func (s *Client) initSigners() error {
	if len(s.signers) > 0 {
		s.settings.Logger().DebugLn("Signers already initialized")
		return nil
	}

	signers := make([]gossh.Signer, 0, len(s.privateKeys))
	for i, keypath := range s.privateKeys {
		key, _, err := utils.ParseSSHPrivateKey(
			[]byte(keypath.Key),
			fmt.Sprintf("index %d", i),
			utils.NewDefaultPassphraseOnlyConsumer(keypath.Passphrase),
		)
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

func (s *Client) stopAllAndLogErrors(cause string) {
	errors := s.stopAll(cause)

	if len(errors) > 0 {
		s.debug("Have %d errors after stop:", len(errors))
	}
	for _, err := range errors {
		s.debug(err.Error())
	}
}

func (s *Client) stopAll(cause string) []error {
	s.debug("Stop client after %s...", cause)

	errors := make([]error, 0)
	addError := func(e error, format string, v ...any) {
		prefix := fmt.Sprintf(format, v...)
		errors = append(errors, fmt.Errorf("%s: %w", prefix, e))
	}

	closeBastionAndAgent := func() {
		if err := utils.SafeClose(s.bastionClient, s.logPresentHandler("Bastion client")...); err != nil {
			addError(err, "Failed to close agent connection")
		}

		if err := utils.SafeClose(s.agentConnection, s.logPresentHandler("Agent")...); err != nil {
			addError(err, "Failed to close agent connection")
		}
	}

	if govalue.Nil(s.sshClient) {
		// we can stop in Start
		// client is nil but agent and bastion prepared
		// try to close. it is safe
		closeBastionAndAgent()
		s.debug("No SSH client found to stop. Exiting...")
		return errors
	}

	s.debug("SSH client and its routines stopping...")

	s.debug("Stopping kube proxies...")
	for _, p := range s.kubeProxies {
		p.StopAll()
	}
	s.kubeProxies = nil

	s.debug("Closing sessions...")
	for indx, sess := range s.sshSessionsList {
		if govalue.Nil(sess) {
			continue
		}

		if err := sess.Signal(gossh.SIGKILL); err != nil {
			addError(err, "Failed to kill session %d", indx)
		}

		if err := sess.Close(); err != nil {
			addError(err, "Failed to close session %d: %v", indx, err)
		}
	}
	s.sshSessionsList = nil

	// by starting kubeproxy on remote, there is one more process starts
	// it cannot be killed by sending any signal to his parrent process
	// so we need to use killall command to kill all this processes
	s.debug("Stopping kube proxies on remote...")
	if err := s.stopRemoteKubeProxies(); err != nil {
		addError(err, "Failed to stop kube proxy")
	}

	s.debug("Stopping keep-alive goroutine...")
	if s.stopChan != nil {
		s.stopChan <- struct{}{}
	}

	err := s.sshClient.Close()
	if err != nil {
		addError(err, "Failed to close ssh client")
	}

	if err := utils.SafeClose(s.sshConn); err != nil {
		addError(err, "Failed to close ssh connection")
	}

	if err := utils.SafeClose(s.sshNetConn); err != nil {
		addError(err, "Failed to close net ssh connection")
	}

	closeBastionAndAgent()

	return errors
}

func (s *Client) registerSession(sess *gossh.Session) {
	s.sshSessionsMu.Lock()
	defer s.sshSessionsMu.Unlock()
	s.sshSessionsList = append(s.sshSessionsList, sess)
}

func (s *Client) stopRemoteKubeProxies() error {
	ctx := s.ctx
	if govalue.Nil(ctx) {
		ctx = context.Background()
	}

	cmd := NewSSHCommand(s, "killall kubectl")

	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd.Sudo(cctx)
	if err := cmd.Run(cctx); err != nil {
		return err
	}

	s.debug("Kube proxies on remote were stopped")
	return nil
}

func (s *Client) debug(format string, v ...any) {
	s.settings.Logger().DebugF(format, v...)
}

func (s *Client) logPresentHandler(connectionName string) []utils.PresentCloseHandler {
	return []utils.PresentCloseHandler{
		func(isPresent bool) {
			if !isPresent {
				return
			}

			s.debug("%s connection is present. Try to close...", connectionName)
		},
	}
}
