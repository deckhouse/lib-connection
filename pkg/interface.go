// Copyright 2026 Flant JSC
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

package pkg

import (
	"context"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/retry"

	"github.com/deckhouse/lib-connection/pkg/ssh/session"
)

type SSHProvider interface {
	// Client
	// get current client or initialize from defaults
	// after SwitchClient and SwitchToDefault Client will return client initialized
	// in SwitchClient and SwitchToDefault method
	Client(ctx context.Context) (SSHClient, error)

	// NewAdditionalClient
	// initialize new client from default configuration
	// use this method if you need more clients not only current
	// this method create client from current client setting or from default configuration
	// for example if you call SwitchClient next calls of NewAdditionalClient
	// create clients for session and private keys passed from SwitchClient
	// implementations can store all created clients with NewAdditionalClient
	// for stopping in Cleanup
	NewAdditionalClient(ctx context.Context) (SSHClient, error)

	// SwitchClient
	// switch current client with new client with provided settings
	// method will stop current client but not stop clients created with NewAdditionalClient
	SwitchClient(ctx context.Context, sess *session.Session, privateKeys []session.AgentPrivateKey) (SSHClient, error)

	// SwitchToDefault
	// switch current client to client with default settings
	// method will stop current client but not stop clients created with NewAdditionalClient
	SwitchToDefault(ctx context.Context) (SSHClient, error)

	// Cleanup
	// stop current client and all clients created with NewAdditionalClient
	// and remove all temporary files like private keys with content got from ConnectionConfig
	// Cleanup safe for call if no any clients consumed from provider
	Cleanup(ctx context.Context) error
}

type Provider interface {
	SSHProvider() SSHProvider
	Cleanup(ctx context.Context) error
}

type Interface interface {
	Command(name string, args ...string) Command
	File() File
	UploadScript(scriptPath string, args ...string) Script
}

type Command interface {
	Run(ctx context.Context) error
	Cmd(ctx context.Context)
	Sudo(ctx context.Context)

	StdoutBytes() []byte
	StderrBytes() []byte
	Output(context.Context) ([]byte, []byte, error)
	CombinedOutput(context.Context) ([]byte, error)

	OnCommandStart(fn func())
	WithEnv(env map[string]string)
	WithTimeout(timeout time.Duration)
	WithStdoutHandler(h func(line string))
	WithStderrHandler(h func(line string))
	WithSSHArgs(args ...string)
}

type File interface {
	Upload(ctx context.Context, srcPath, dstPath string) error
	Download(ctx context.Context, srcPath, dstPath string) error

	UploadBytes(ctx context.Context, data []byte, remotePath string) error
	DownloadBytes(ctx context.Context, remotePath string) ([]byte, error)
}

type Script interface {
	Execute(context.Context) (stdout []byte, err error)
	ExecuteBundle(ctx context.Context, parentDir, bundleDir string) (stdout []byte, err error)

	Sudo()
	WithStdoutHandler(handler func(string))
	WithTimeout(timeout time.Duration)
	WithEnvs(envs map[string]string)
	WithCleanupAfterExec(doCleanup bool)
	WithCommanderMode(enabled bool)
	WithExecuteUploadDir(dir string)
}

type Tunnel interface {
	Up(ctx context.Context) error

	HealthMonitor(errorOutCh chan<- error)

	Stop()

	String() string
}

type ReverseTunnelChecker interface {
	CheckTunnel(context.Context) (string, error)
}

type ReverseTunnelKiller interface {
	KillTunnel(context.Context) (string, error)
}

type ReverseTunnel interface {
	Up() error

	StartHealthMonitor(ctx context.Context, checker ReverseTunnelChecker, killer ReverseTunnelKiller)

	Stop()

	String() string
}

type KubeProxy interface {
	Start(useLocalPort int) (port string, err error)

	StopAll()

	Stop(startID int)
}

type Check interface {
	WithDelaySeconds(seconds int) Check

	AwaitAvailability(context.Context, retry.Params) error

	CheckAvailability(context.Context) error

	ExpectAvailable(context.Context) ([]byte, error)

	String() string
}

type SSHLoopHandler func(s SSHClient) error

type SSHClient interface {
	// 	BeforeStart safe starting without create session. Should safe for next Start call
	OnlyPreparePrivateKeys() error

	Start() error

	// Tunnel is used to open local (L) and remote (R) tunnels
	Tunnel(address string) Tunnel

	// ReverseTunnel is used to open remote (R) tunnel
	ReverseTunnel(address string) ReverseTunnel

	// Command is used to run commands on remote server
	Command(name string, arg ...string) Command

	// KubeProxy is used to start kubectl proxy and create a tunnel from local port to proxy port
	KubeProxy() KubeProxy

	// File is used to upload and download files and directories
	File() File

	// UploadScript is used to upload script and execute it on remote server
	UploadScript(scriptPath string, args ...string) Script

	// UploadScript is used to upload script and execute it on remote server
	Check() Check

	// Stop the client
	Stop()

	// Loop Looping all available hosts
	Loop(fn SSHLoopHandler) error

	Session() *session.Session

	PrivateKeys() []session.AgentPrivateKey

	RefreshPrivateKeys() error

	IsStopped() bool
}
