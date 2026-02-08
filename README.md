# lib-connection

Deckhouse connection to nodes over SSH and kube-api over SSH and directly implementations.

Library provide interfaces and own implementations for SSH and kubernetes client.
Also library provide special providers for getting clients (more information about this below).
Please DO NOT CREATE implementations of clients directly without need. Please use providers for it.

## SSH client

Interface of SSH client (`SSHClient`) described [here](./pkg/ssh.go).
With this interface we can run commands, upload and download files, run scripts and bundles,
up tunnel and reverse tunnels and up kubernetes proxy for access to create kubernetes client running over ssh.

Now, we have 3 implementations of `SSHClient`
- [cli](./pkg/ssh/clissh) - use `ssh` and `scp` binaries for ssh routines. If you use your own bin path
for these binaries you should add bin path to `PATH` env before use.
- [go](./pkg/ssh/gossh) - use [own fork](https://github.com/deckhouse/lib-gossh) of [crypto](https://pkg.go.dev/golang.org/x/crypto/ssh)
library. We use own with adding additional logging
- [testssh](./pkg/ssh/testssh) - our mock for testing purposes without connection to ssh.

All implementations contain monitors and auto reconnecting to ssh, tunnels and kube-proxy if connection
was failed. 

`Script` implementations contains method `ExecuteBundle` for running script that run list of scripts
named as `bundle` as output progress of running ([see implementation here](./pkg/ssh/utils/bundle.go)). 
By default, it runs `bashible` bundle from [deckhouse](https://github.com/deckhouse/deckhouse/blob/main/candi/bashible/bashible.sh.tpl).
If you need run your own bundle pass bundler options `BundlerOption` with `Script.WithBundlerOpts` method.

Also library provides `Interface` interface for running commands and scrip routines on local machine.

## Kube client

Interface of SSH client (`KubeClient`) described [here](./pkg/kube.go). It implements `client-go` client
interface with some additional methods.

Now, we have two implementations of this interface:
- [KubernetesClient](./pkg/kube/client.go) - [use](https://github.com/flant/kube-client) library this
implementation can work with kubeconfig, rest client, local run and over SSH with kube-proxy
- [ErrorKubernetesClient](./pkg/kube/error_client.go) - it always returns error for all calls. It needs
for prevent using closed kube client (more information about this below).

`KubeClient` can stop with `Stop` method. If using over SSH connection it stops kube-proxy and client 
if passed `full` flag. Also `Stop` method switch inner `KubeClient` to `ErrorKubernetesClient` for
prevent using closed client and do not additional attempts to kube-proxy.

## Clients providers interfaces

Library implement own interfaces to provide clients for creating clients for lightweight usage in your routines.

### SSHProvider

Described [here](./pkg/ssh.go) as `SSHProvider`. Have next interface:
- `Client` - this provides SSH client for default settings passed in provider. Implementations should cache
current client. You should use this method for getting `SSHClient`. Please do not stop this client directly.
- `SwitchClient` - switch current `SSHClient` with new settings. It needs if you first connect with defaults
but in you logic we need to use new connection. For example, you connect to master, create new user and should
continue working with new user. It will close current `SSHClient` if this got via `Client` method, but safe
if `Client` did not call. Warning! This method returns `SSHClient`, but DO NOT SAVE it your structures.
Please use `Client` for getting current client.
Example usage:
```go
package my
func do(){
	// ini provider
	// provider.Client()
	// ...
	// creating new user over default client
	// provider.SwitchClient()
	// provider.Client()
	// ...
	// provider.Client()
	// ...
}
```
- `SwitchToDefault` - it uses if you need to use default configuration client after `SwitchClient`.
For example, For example, you connect to master, create new user do all routines with new user
and continue with default. It will close current `SSHClient` if this got via `Client` or `SwitchClient`
method, but safe if `Client` or/and `SwitchClient` did not call. Warning! This method returns 
`SSHClient`, but DO NOT SAVE it your structures. Please use `Client` for getting current client.
Example usage:
```go
package my
func do(){
	// ini provider
	// provider.Client()
	// ...
	// creating new user over default client
	// provider.SwitchClient()
	// provider.Client()
	// ...
	// provider.SwitchToDefault()
	// provider.Client()
	// delete created user over default client
	// ...
}
```
- `NewAdditionalClient` - creates new additional client with default configuration. It needs if you want
to use another connection without affect current client. Provider save all clients created via this method
for cleanup. If clients does not need anymore you can stop it with `Stop` method
- `NewStandaloneClient` - creates new standalone client. It needs if you need to connect to another hosts.
Provider save all clients created via this method for cleanup. If clients does not need anymore 
you can stop it with `Stop` method.
- `Cleanup` - provider can provide some files for its routines like private keys passed from configuration.
This files will delete in this call. Also, it stops current client and all additional clients created with
`NewAdditionalClient` and `NewStandaloneClient`. It is safe if provider does not have current client or
additional clients. Also, it is safe if some or all clients were stopped. Current client and all additional
will remove from provider. Use this method in end of your logic.

Now we have two implementations of `SSHProvider`: `DefaultSSHProvider`, `SSHProvider` in `testssh` package
and `ErrorSSHProvider`.

#### DefaultSSHProvider

DefaultSSHProvider provide clients with configuration passed default configuration.

Configuration can provide with [this](./pkg/ssh/config/config.go).

You can create this configuration (`ConnectionConfig` struct) directly 
or with [parse flags](./pkg/ssh/config/parse_flags.go) or with parse 
[configuration document](./pkg/ssh/config/parse_config.go). Document schemas described
[here](./pkg/ssh/config/openapi/). If you need to provide configuration in your project 
(for example, render documentation by specs), you can download these schemas in CI or makefile or directly.
You can see can you download specs over GitHub API in [makefile](./Makefile) `validation/license/download`
target. 

###### ParseConnectionConfig

`ParseConnectionConfig` gets reader with documents and returns `ConnectionConfig` struct.
By default, `ParseConnectionConfig` not allow configuration without hosts and with unknown kinds.
For redeclare it, please use `ParseWithRequiredSSHHost` and `ParseWithSkipUnknownKinds` options.
Also, `ParseConnectionConfig` add some additional checks, like that private keys parsed (with provided
password if password set) and that `legacyMode` and `modernMode` set both.

###### ParseFlags

`FlagsParser` provide `ConnectionConfig` from cli arguments. It is use `https://github.com/spf13/pflag` package for parse it.
All flags can rewrite with env variables [described in](./pkg/ssh/config/parse_flags.go). You can 
provide prefix for envs variables with `WithEnvsPrefix` method. Parse flags doing in next order:
```go
package my

import "os"

func do() error {
	// create and prepare parser
	parser := NewFlagsParser()
	parser.WithEnvsPrefix("DHCTL")
	// init flags or you can pass your flagset, parser skip unknown flags
	fset := flag.NewFlagSet("my-set", flag.ExitOnError)
	flags, err := parser.InitFlags(fset)
	if err != nil {
		return err
	}
	// or you can provide your ouwn arguments slice
	err = flags.Parse(os.Args[1:])
	if err != nil {
		return err
	}

	// you can use ValidateOption for configure parse
	config, err := parser.ExtractConfigAfterParse(flags)
	if err != nil {
		return err
    }
	
	return nil
}
```

Flags parsers uses copy of passed flag set for parsing. If you need parse with you another flags set
you can get new flag set with `FlagSet` method and parse flag set by your hand.
After parse, extract `ConnectionConfig` with `ExtractConfigAfterParse` method.

By default, hosts is not required for parse, you can rewrite with `ParseWithRequiredSSHHost`.
`ExtractConfigAfterParse` add some defaults if some flags not passes, like port and bastion port (22 by default),
user and bastion user (current user from USER env or getting with sys cals).
Also, by default flags parser add `~/.ssh/id_rsa` private key. In some cases it is not required:
if user uses password auth (without private key) or if user want to use ssh agent private keys only.
For force use password auth key user should pass `--force-no-private-keys` with `--ask-become-pass` flags.
For force only ssh-agent private keys user should pass `--force-no-private-keys` with 
`--use-agent-with-no-private-keys` flags and set `SSH_AUTH_SOCK` (in this case parser check that this
env value is exists file).
Flags parser also doing some additional checks for parsed flags:
- private keys files should parse as valid private key. If private key protected with password, parser
ask password for key from terminal. If you need set your own extract logic, please set extractor with
`WithPrivateKeyPasswordExtractor` method
- `--ssh-legacy-mode` and `--ssh-modern-mode` should not provide both
- if pass `--ask-become-pass` or/and `--ask-bastion-pass` parser ask passwords from terminal.
If you need set your getting passwords logic, you can provide your func with `WithAsk` method, like here:
```go
package my
func do {
	// ...
	parser.WithAsk(func(promt string) ([]byte, error) {
		switch promt {
		case "[bastion] Password: ":
			return []byte("not secure bastion password"), nil
		case "[sudo] Password: ":
			return []byte("not secure sudo password"), nil
		default:
			return nil, fmt.Errorf("unknown prompt %s", promt)
		}
	})
}
```
- also, parsers checks that auth method was provided (private keys, sudo pass, use agent private keys).

User can pass document file with connection config via `--connection-config` flag. If this flag provided
parser returns `ConnectionConfig` parsed with `ParseConnectionConfig`. If user pass connection config path
with another flags, parser returns error.

###### Create `ConnectionConfig` directly

If you create `ConnectionConfig` and want to use ssh-agent only, please set `ForceUseSSHAgent` field to true.
`AgentPrivateKey` can proccess Key field as content or file path. If you provide key as file please 
set `IsPath` field to true.

##### DefaultSSHProvider logic

User can pass private keys with `ConnectionConfig` as file path or content. If it uses as content,
`DefaultSSHProvider` creates  temp files with private keys, because internal logic process private keys
as file. All files will delete on `Cleanup` call.
Also, in creating all clients (additional, standalone, switch) provider adds private keys from default
configuration by default. For example, if you switch client, you could not add private keys from current 
client for safe switching.

`DefaultSSHProvider` provide client implementations with next rules:
- if you provide `SSHClientWithForceGoSSH` option it returns go-ssh
- if set `ForceModern` in configuration returns go-ssh
- if set `ForceLegacy` in configuration returns cli-ssh
- if configuration does not contain private keys returns go-ssh, because cli-ssh not supported
password authentification
- by default returns cli-ssh. Warning! this behaviour can change in the future.

By default, provider not start client if you need you can pass `SSHClientWithStartAfterCreate` option.

##### ErrorSSHProvider

This provider returns error for every call. This provider can use with `KubeProvider` if you sure
that you need to use kube client not over ssh.

###### SSHProvider in `testssh`

You can pass this provider in unit tests. This provider save all switch calls and you can test it.

### KubeProvider

Provides kubernetes client. Have next methods:
- `Client` - gets current client or init new if current client not set. Client cached.
If you client in retry loop, please call `Client` on every iteration. 
And please do not save client in your structures, please call `Client` with every kube-api routine. 
And do not stop this client directly.
- `NewAdditionalClient` - initialize new client. Need use if you do not want affect current client.
If you do not need a client, you can call `kube.Stop` method for stop client and its inferiors.
All clients created with this method saved in provider.
- `NewAdditionalClientWithoutInitialize` - create new client, but not initialize it. For start client
please use `client.InitContext`. Need use if you do not want affect current client.
All clients created with this method saved in provider.
- `Cleanup` - stops all additional clients got from NewAdditionalClient and NewAdditionalClientWithoutInitialize
also current client also stop, but not fully because if we use over ssh current client can use in another routines.
Call `Cleanup` is safe for call on stopped clients.

Now, we have next implementations:
- `DefaultKubeProvider` - provide default client with its config
- `FakeKubeProvider` - provide fake clients for using in tests.

#### DefaultKubeProvider

DefaultKubeProvider creates kube provider dependent on passed user configuration.
Configuration described [here](./pkg/kube/config.go)

Kube client creates with in next order:
- if set `config.KubeConfigInCluster` provider will use `in-cluster` configuration. This
should use for creating kube client in containers in k8s cluster
- if set `config.KubeConfig` (path to kubeconfig) uses this kubeconfig for connection
- if set `config.RestConfig` uses this configuration for connect to kube API. It needs
if you want to use BearerToken for connect. 
- if set `config.LocalKubeClient` use directly connection on same host
- by default uses kube proxy over ssh.

##### Parse configuration from flags

You can use `kube.FlagsParser` for extract configuration from cli flags.
This parser have same rules as [ssh flags parser](#parseflags). Client can provide
kubeconfig path with context in kubeconfig or `in-cluster` mode only. For another options like
local or rest config you can prepare configuration in code.
`FlagsParser` have next additional checks:
- fail if `in-cluster` mode pass with kubeconfig path
- if kubeconfig provided, parser checks that provide valid kubeconfig
- if pass context, provider checks that kubeconfig contains this context.

Warning! Parser also checks `KUBECONFIG` env. If this env sets, parser use value from env as
kubeconfig path.

##### Provider initialization and logic

For init provider, you can pass special interface `RunnerInterface` this interface provide routines
to additional logic used depend on configuration. For getting implementation use `GetRunnerInterface`
This function checks that configuration is not conflicted (use one connection method)
For kubeconfig, `in-cluster` and rest config modes, implementations does not contain complex logic.
But for ssh logic is complex.

###### Kube-proxy (over ssh) mode

`RunnerInterfaceSSH` got `SSHProvider` for provide client for starting kube-proxy

For call `Client` provider (in fact `RunnerInterfaceSSH`) use `SSHProvider.Client()` method.
For every call, provider checks that ssh-client configuration is same with current.
If it is same, returns current saved kube client. Otherwise, provider initialize new kube client
with got `SSHClient`. Also, during initialization it checks that ssh host available and switch to
another host if it needs. After initialize new kube client stops current kube-client, but not fully.
This logic needs for simple usage `KubeProvider` you do not need track ssh switches in your logic.
And that's why you need `Client` call for every kube API interaction.

`NewAdditionalClient` and `NewAdditionalClientWithoutInitialize` always create new ssh-client with
`sshProvider.NewAdditionalClient`. That's why you can stop this kube-clients fully. All these clients
saved to internals for cleanup.

Before returns new kube-client, provider checks, that kube API is available.

`Cleanup` - stops all additional clients fully, but current stop not fully (only kube-proxy), because
current kube-client uses current ssh-client but this client can use in the next operations in your code.

#### FakeKubeProvider

Provides fake kube client.

In creation, `FakeKubeProvider` creates current kube-client and returns this client for all methods.
It needs for test resources if you use additional clients in one place without saving additional
clients in your code. You can use `Client` call for getting kube client after test your methods and
asserts resources after test. 
`KubernetesClient.InitContext` is save for call with fake client