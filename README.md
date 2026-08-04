# lib-connection

Deckhouse SSH implementation for connecting to nodes and Kubernetes API over SSH and directly.

This library provides interfaces and implementations for SSH and Kubernetes clients.
Also, this library provides special providers for getting clients (more information about this below).
Please DO NOT CREATE implementations of clients directly unless needed. Please use providers for this.

## Global settings

Library routines need some global settings for running routines.
These are described as the Settings interface [here](./pkg/settings/settings.go). An implementation can be created
with the `NewBaseProviders` constructor. Currently we have the following settings:

- `Logger` - a `*slog.Logger` used for all library logging, passed directly (no wrapper interface).
If not set, it defaults to `slog.Default()`. Pass your own `*slog.Logger` (e.g. with a debug-level handler)
if you need debug logs.
- `NodeTmpDir` - used for uploading bundles and some additional temporary files to a remote nodes.
Default path is `/opt/deckhouse/tmp`
- `NodeBinPath` - currently used only for kube-proxy to add this path to the `PATH` env, because
we use our own path to safely store kubectl on the node. Default - `/opt/deckhouse/bin`
- `IsDebug` - enables some routines with debug
- `TmpDir`  - root tmp dir, defaults to `os.TmpDir() + "/dhctl"`
- `AuthSock` - ssh-agent auth socket; if not set, uses `os.Getenv("SSH_AUTH_SOCK")` for every call.
- `EnvsPrefix` - env prefix for flag parsers. Default is empty string.
- `OnShutdown` - function to add some routines at the end of your logic. Default is a no-op.
You can use the `tomb` package in dhctl for this.

## SSH client

The interface of the SSH client (`SSHClient`) is described [here](./pkg/ssh.go).
With this interface we can run commands, upload and download files, run scripts and bundles,
set up tunnels and reverse tunnels, and set up a Kubernetes proxy for accessing Kubernetes API over SSH.

Currently, we have 3 implementations of `SSHClient`:

- [cli](./pkg/ssh/clissh) - uses `ssh` and `scp` binaries for SSH routines. If you use your own binaries path
for these you should add the your path to the `PATH` env beforehand.
- [go](./pkg/ssh/gossh) - uses an [our own fork](https://github.com/deckhouse/lib-gossh) of the [crypto](https://pkg.go.dev/golang.org/x/crypto/ssh)
library. We added additional logging.
- [testssh](./pkg/ssh/testssh) - mock for testing purposes. No SSH needed.

All implementations provide connection monitoring and reconnect automatically to SSH, tunnels, and kube-proxy if the connection
fails.

`Script` implementations contain the method `ExecuteBundle` for running a script that runs a list of scripts
named as `bundle` as output progress of running ([see implementation here](./pkg/ssh/utils/bundle.go)).
By default, it runs the `bashible` bundle from [deckhouse](https://github.com/deckhouse/deckhouse/blob/main/candi/bashible/bashible.sh.tpl).
If you need to run your own bundle, pass bundler options `BundlerOption` with the `Script.WithBundlerOpts` method.

Also, the library provides an `Interface` interface for running commands and script routines on the local machine.

## Kubernetes client

The interface of the Kube client (`KubeClient`) is described [here](./pkg/kube.go). It implements the `client-go` client
interface with some additional methods.

Currently, we have two implementations of this interface:

- [KubernetesClient](./pkg/kube/client.go) - uses the [kube-client](https://github.com/flant/kube-client) library; this
implementation can work with kubeconfig, rest client, local run, and over SSH via kube-proxy.
- [ErrorKubernetesClient](./pkg/kube/error_client.go) - it always returns an error for all calls. It is required
to prevent use of a closed kube client (more information about this below).

`KubeClient` can be stopped with the `Stop` method. If used over an SSH connection it stops kube-proxy and the client
if the `full` flag is passed. Also, the `Stop` method switches the inner `KubeClient` to `ErrorKubernetesClient` to
prevent use of a closed client and avoid additional attempts to reach kube-proxy.

## Clients providers interfaces

Library implements its own interfaces to provide clients for lightweight usage in your routines.

### SSHProvider

Described [here](./pkg/ssh.go) as `SSHProvider`. Has the following interface:

- `Client` - provides an SSH client for default settings passed in the provider. Implementations should cache
the current client. You should use this method for getting `SSHClient`. Please do not stop this client directly.
- `SwitchClient` - switches the current `SSHClient` with new settings. This is needed if you first connect with defaults
but in your logic you need to use a new connection. For example, you connect to master, create a new user, and should
continue working with the new user. It will close the current `SSHClient` if it was obtained via the `Client` method, but is safe
if `Client` was not called. Warning! This method returns `SSHClient`, but DO NOT SAVE it in your structures.
Please use `Client` for getting the current client.
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

- `SwitchToDefault` - used if you need to use the default configuration client after `SwitchClient`.
For example, you connect to master, create a new user, do all routines with the new user,
and continue with the default. It will close the current `SSHClient` if it was obtained via `Client` or `SwitchClient`,
but is safe if `Client` or/and `SwitchClient` were not called. Warning! This method returns
`SSHClient`, but DO NOT SAVE it in your structures. Please use `Client` for getting the current client.
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

- `NewAdditionalClient` - creates a new additional client with the default configuration. This is needed if you want
to use another connection without affecting the current client. The provider saves all clients created via this method
for cleanup. If clients are no longer needed you can stop them with the `Stop` method.
- `NewStandaloneClient` - creates a new standalone client. This is needed if you need to connect to other hosts.
The provider saves all clients created via this method for cleanup. If clients are no longer needed
you can stop them with the `Stop` method.
- `Cleanup` - the provider may create some files for its routines, like private keys passed from configuration.
These files will be deleted in this call. Also, it stops the current client and all additional clients created with
`NewAdditionalClient` and `NewStandaloneClient`. It is safe if the provider does not have a current client or
additional clients. Also, it is safe if some or all clients were stopped. The current client and all additional clients
will be removed from the provider. Use this method at the end of your logic.

Currently we have three implementations of `SSHProvider`: `DefaultSSHProvider`, `SSHProvider` in the `testssh` package,
and `ErrorSSHProvider`.

#### StandaloneClientProvider

`StandaloneClientProvider` is an optional capability of an `SSHProvider`, described [here](./pkg/ssh.go). It adds two
methods:

- `StandaloneClientFor` - returns a started and `Live` client for the passed key. The cached client for the key is
reused while it is alive; a dead client is stopped and replaced in place, so the provider keeps at most one client per
key. Unlike `NewStandaloneClient`, the client is always started, regardless of the provider start option. If creation
fails, nothing is cached and the next call retries. Keyed clients are stopped in `Cleanup` too. Note that the client is
`Live` at return time only: a connection can die later, so command errors still must be handled.
- `StopStandaloneClientFor` - stops the client cached for the key and drops it from the registry, so the next
`StandaloneClientFor` with the same key creates a new one. A creation for the same key still in flight is aborted as
well. Call it as soon as the target of the key is gone, for example a node removed by a converge: nothing else stops a
keyed client before `Cleanup`, so until then it keeps its keep-alive and reconnects to a target which will never answer.

The key only identifies a target for the caller, the connection target comes from the session, so build a session per
target instead of passing one session under different keys.

All implementations of `SSHProvider` from this library implement this interface. Example usage:

```go
package my

func runOnNode(ctx context.Context, p connection.StandaloneClientProvider, node session.Host, sess *session.Session) error {
	nodeSession := sess.Copy()
	nodeSession.SetAvailableHosts([]session.Host{node})

	// the node outlives this function, so the client is stopped by the code which removes
	// the node, not here
	// a dead connection is detected by keep-alive and replaced only after the reconnect budget
	// of the client, so the retry budget of the loop should exceed it
	return retry.NewLoop("run on node", 30, 10*time.Second).RunContext(ctx, func() error {
		// returns the cached client or a new one if the previous connection died
		client, err := p.StandaloneClientFor(ctx, node.Name, nodeSession, nil)
		if err != nil {
			return fmt.Errorf("get client for node %s: %w", node.Name, err)
		}

		return client.Command("uname", "-a").Run(ctx)
	})
}

func removeNode(ctx context.Context, p connection.StandaloneClientProvider, node session.Host) error {
	// the client of a removed node has nothing to reconnect to
	defer p.StopStandaloneClientFor(ctx, node.Name)

	return deleteNodeSomehow(ctx, node)
}
```

#### DefaultSSHProvider

DefaultSSHProvider provides clients with the configuration passed as default configuration.

Configuration can be provided with [this](./pkg/ssh/config/config.go).

You can create this configuration (`ConnectionConfig` struct) directly
or with [parse flags](./pkg/ssh/config/parse_flags.go) or with a parsed
[configuration document](./pkg/ssh/config/parse_config.go). Document schemas are described
[here](./pkg/ssh/config/openapi/). If you need to provide configuration in your project
(for example, render documentation by specs), you can download these schemas in CI, a makefile, or directly.
You can see how to download specs over the GitHub API in the [makefile](./Makefile) `validation/license/download`
target.
You do not need to get these schemas for validation. The library embeds these schemas and loads them if needed.
But you can get strings of schemas in code with the `ConfigurationOpenAPISpec` and
`HostOpenAPISpec` functions.

###### ParseConnectionConfig

`ParseConnectionConfig` gets a reader with documents and returns a `ConnectionConfig` struct.
By default, `ParseConnectionConfig` does not allow configuration without hosts and with unknown kinds.
To override this, please use the `ParseWithRequiredSSHHost` and `ParseWithSkipUnknownKinds` options.
Also, `ParseConnectionConfig` adds some additional checks, like that private keys are parsed (with the provided
password if a password is set) and that `legacyMode` and `modernMode` are not both set.

###### ParseFlags

`FlagsParser` provides `ConnectionConfig` from CLI arguments. It uses the [pflag lib](https://github.com/spf13/pflag) for parsing.
All flags can be overridden with env variables [described in](./pkg/ssh/config/parse_flags.go). You can
provide a prefix for env variables with the `WithEnvsPrefix` method. Flags are parsed in the following order:

```go
package my

import (
	"context"
	"os"

	flag "github.com/spf13/pflag"

	"github.com/deckhouse/lib-connection/pkg/settings"
	sshconfig "github.com/deckhouse/lib-connection/pkg/ssh/config"
)

func do(ctx context.Context, sett settings.Settings) error {
	// create and prepare parser
	parser := sshconfig.NewFlagsParser(ctx, sett)
	parser.WithEnvsPrefix("DHCTL")

	// init flags, or you can pass your own flag set; the parser skips unknown flags
	fset := flag.NewFlagSet("my-set", flag.ExitOnError)
	flags, err := parser.InitFlags(fset)
	if err != nil {
		return err
	}

	// you can use ValidateOption to configure parsing, e.g. sshconfig.ParseWithRequiredSSHHost(true)
	config, err := flags.ExtractConfig(os.Args[1:])
	if err != nil {
		return err
	}

	// if you need to parse your own flag set, you should parse it by hand
	if err := fset.Parse(os.Args[1:]); err != nil {
		return err
	}

	_ = config

	return nil
}
```

The flags parser uses an internal flag set for parsing. If you need to parse with another flags set
you should parse your flag set by hand. However, the parser adds a "fake" flag set
to the passed flag set. This is needed to add information about its own flags to the output.
If we were using your flag set, the parser could add multiple values in slices, for example,
in help. Your flags can be parsed before or after parsing the parser's own flags.

By default, hosts are not required for parsing; you can override this with `ParseWithRequiredSSHHost`.
This is needed because we can parse SSH configuration and kube configuration both, and if we have a kubeconfig
path we should skip all SSH flags and an empty flag set for SSH is valid in this case.
But we can use the `OverSSH` method in kube configuration. Note that you can use SSH routines and kube
in one logic, and we can use kubeconfig for kube connection.
`ExtractConfig` adds some defaults if some flags are not passed, like port and bastion port (22 by default),
user and bastion user (current user from the USER env or obtained with syscalls).
Also, by default the flags parser adds the `~/.ssh/id_rsa` private key. In some cases this is not required:
if the user uses password auth (without a private key) or if the user wants to use SSH agent private keys only.
To force password auth, the user should pass `--force-no-private-keys` with `--ask-become-pass` flags.
To force SSH-agent private keys only, the user should pass `--force-no-private-keys` with
`--use-agent-with-no-private-keys` flags and set `SSH_AUTH_SOCK` (in this case the parser checks that this
env value exists as a file).
The flags parser also performs some additional checks on parsed flags:

- private key files should parse as valid private keys. If a private key is protected with a password, the parser
asks for the password from the terminal. If you need to set your own extraction logic, please set an extractor with
the `WithPrivateKeyPasswordExtractor` method.
- `--ssh-legacy-mode` and `--ssh-modern-mode` should not both be provided.
- if `--ask-become-pass` or/and `--ask-bastion-pass` are passed, the parser asks for passwords from the terminal.
If you need to set your own password-getting logic, you can provide your func with the `WithAsk` method, like here:

```go
package my
func do {
 // ...
 parser.WithAsk(func(prompt string) ([]byte, error) {
  switch prompt {
  case "[bastion] Password: ":
   return []byte("not secure bastion password"), nil
  case "[sudo] Password: ":
   return []byte("not secure sudo password"), nil
  default:
   return nil, fmt.Errorf("unknown prompt %s", prompt)
  }
 })
}
```

- also, the parser checks that an auth method was provided (private keys, sudo pass, use agent private keys).

The user can pass a document file with connection config via the `--connection-config` flag. If this flag is provided,
the parser returns `ConnectionConfig` parsed with `ParseConnectionConfig`. If the user passes a connection config path
with other flags, the parser returns an error.

###### Create `ConnectionConfig` directly

If you create `ConnectionConfig` and want to use SSH-agent only, please set the `ForceUseSSHAgent` field to true.
`AgentPrivateKey` can process the Key field as content or a file path. If you provide a key as a file, please
set the `IsPath` field to true.

##### DefaultSSHProvider logic

The user can pass private keys with `ConnectionConfig` as a file path or content. If used as content,
`DefaultSSHProvider` creates temp files with private keys, because the internal logic processes private keys
as files. All files will be deleted on the `Cleanup` call.
Also, when creating all clients (additional, standalone, switch), the provider adds private keys from the default
configuration by default. For example, if you switch the client, previous private keys from the current
client are not added to avoid unsafe switching.

`DefaultSSHProvider` provides client implementations with the following rules:

- if you provide the `SSHClientWithForceGoSSH` option it returns go-ssh
- if `ForceModern` is set in the configuration, returns go-ssh
- if `ForceLegacy` is set in the configuration, returns cli-ssh
- by default returns go-ssh

By default, the provider does not start the client; if you need it to, you can pass the `SSHClientWithStartAfterCreate` option.

`DefaultSSHProvider` initializes a new agent by default for cli-ssh, but if `ForceUseSSHAgent` is set a new agent is not started.
Also, you can skip running the agent with the `SSHClientWithNoInitializeAgent` option.

##### ErrorSSHProvider

This provider returns an error for every call. This provider can be used with `KubeProvider` if you are sure
that you need to use the kube client not over SSH.

###### SSHProvider in `testssh`

You can pass this provider in unit tests. This provider saves all switch calls and you can test against them.

### KubeProvider

Provides a Kubernetes client. Has the following methods:

- `Client` - gets the current client or initializes a new one if no current client is set. The client is cached.
If you are in a retry loop, please call `Client` on every iteration.
Also, please do not save the client in your structures; please call `Client` with every kube-api routine.
And do not stop this client directly.
- `NewAdditionalClient` - initializes a new client. Use this if you do not want to affect the current client.
If you no longer need a client, you can call the `kube.Stop` method to stop the client and its dependents.
All clients created with this method are saved in the provider.
- `NewAdditionalClientWithoutInitialize` - creates a new client, but does not initialize it. To start the client
please use `client.InitContext`. Use this if you do not want to affect the current client.
All clients created with this method are saved in the provider.
- `Cleanup` - stops all additional clients obtained from NewAdditionalClient and NewAdditionalClientWithoutInitialize;
the current client is also stopped, but not fully, because if used over SSH the current client may be used in other routines.
Calling `Cleanup` is safe on already stopped clients.

Currently, we have the following implementations:

- `DefaultKubeProvider` - provides a default client with its config
- `FakeKubeProvider` - provides fake clients for use in tests.

#### DefaultKubeProvider

DefaultKubeProvider creates a kube provider dependent on the passed user configuration.
Configuration is described [here](./pkg/kube/config.go).

The kube client is created in the following order:

- if `config.KubeConfigInCluster` is set, the provider will use `in-cluster` configuration. This
should be used for creating a kube client in containers in a k8s cluster.
- if `config.KubeConfig` (path to kubeconfig) is set, uses this kubeconfig for connection.
- if `config.RestConfig` is set, uses this configuration to connect to the kube API. This is needed
if you want to use BearerToken for connection.
- if `config.LocalKubeClient` is set, uses a direct connection on the same host.
- by default uses kube proxy over SSH.

##### Parse configuration from flags

You can use `kube.FlagsParser` to extract configuration from CLI flags.
This parser has the same rules as the [SSH flags parser](#parseflags). The client can provide
a kubeconfig path with context in kubeconfig or `in-cluster` mode only. For other options like
local or rest config you can prepare the configuration in code.
`FlagsParser` has the following additional checks:

- fails if `in-cluster` mode is passed with a kubeconfig path
- if kubeconfig is provided, the parser checks that it is a valid kubeconfig
- if a context is passed, the provider checks that the kubeconfig contains this context.

Warning! The parser also checks the `KUBECONFIG` env. If this env is set, the parser uses its value as the
kubeconfig path.

##### Provider initialization and logic

To initialize the provider, you can pass a special interface `RunnerInterface`; this interface provides routines
for additional logic used depending on configuration. To get an implementation use `GetRunnerInterface`.
This function checks that the configuration is not conflicted (uses one connection method).
For kubeconfig, `in-cluster`, and rest config modes, implementations do not contain complex logic.
But for SSH the logic is complex.

###### Kube-proxy (over SSH) mode

`RunnerInterfaceSSH` gets `SSHProvider` to provide a client for starting kube-proxy.

For calling `Client`, the provider (in fact `RunnerInterfaceSSH`) uses the `SSHProvider.Client()` method.
For every call, the provider checks that the SSH client configuration is the same as the current one.
If it is the same, returns the current saved kube client. Otherwise, the provider initializes a new kube client
with the obtained `SSHClient`. Also, during initialization it checks that the SSH host is available and switches to
another host if needed. After initializing the new kube client, the current kube-client is stopped, but not fully.
This logic is needed for simple usage of `KubeProvider`; you do not need to track SSH switches in your logic.
And that is why you need to call `Client` for every kube API interaction.

`NewAdditionalClient` and `NewAdditionalClientWithoutInitialize` always create a new SSH client with
`sshProvider.NewAdditionalClient`. That is why you can stop these kube-clients fully. All these clients
are saved to internals for cleanup.

Before returning a new kube-client, the provider checks that the kube API is available.

`Cleanup` - stops all additional clients fully, but stops the current client not fully (only kube-proxy), because
the current kube-client uses the current SSH client, and this client may be used in the next operations in your code.

#### FakeKubeProvider

Provides a fake kube client.

On creation, `FakeKubeProvider` creates the current kube-client and returns this client for all methods.
This is needed to test resources if you use additional clients in one place without saving additional
clients in your code. You can use the `Client` call to get the kube client after testing your methods and
assert resources after the test.
`KubernetesClient.InitContext` is safe to call with a fake client.

## Usage examples

A full runnable example (cobra commands for kube-only, ssh, and ssh with additional/standalone clients)
is provided [here](./examples/cobra). Please see the code comments there for more details. The snippets
below are condensed variants of the same patterns.

### Minimal SSH client

Build a `ConnectionConfig` directly (no flag parsing) and run a command on a remote host:

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/deckhouse/lib-connection/pkg/provider"
	"github.com/deckhouse/lib-connection/pkg/settings"
	sshconfig "github.com/deckhouse/lib-connection/pkg/ssh/config"
)

func main() {
	ctx := context.Background()
	sett := settings.NewBaseProviders(settings.ProviderParams{})

	config := &sshconfig.ConnectionConfig{
		Hosts: []sshconfig.Host{{Host: "10.0.0.1"}},
		Config: &sshconfig.Config{
			User: "user",
			PrivateKeys: []sshconfig.AgentPrivateKey{
				{Key: "/home/user/.ssh/id_rsa", IsPath: true},
			},
		},
	}

	sshProvider := provider.NewDefaultSSHProvider(sett, config, provider.SSHClientWithStartAfterCreate(true))
	defer func() {
		if err := sshProvider.Cleanup(ctx); err != nil {
			sett.Logger().Error(fmt.Sprintf("cleanup ssh provider: %v", err))
		}
	}()

	client, err := sshProvider.Client(ctx)
	if err != nil {
		log.Fatal(err)
	}

	stdout, _, err := client.Command("uname", "-a").Output(ctx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(stdout))
}
```

### Minimal Kubernetes client (not over SSH)

If your process never needs to reach Kubernetes over an SSH tunnel, pass `ErrorSSHProviderInitializer`
so any accidental attempt to use SSH fails fast instead of silently trying to connect:

```go
package main

import (
	"context"
	"fmt"
	"log"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/deckhouse/lib-connection/pkg/kube"
	"github.com/deckhouse/lib-connection/pkg/provider"
	"github.com/deckhouse/lib-connection/pkg/settings"
)

func main() {
	ctx := context.Background()
	sett := settings.NewBaseProviders(settings.ProviderParams{})

	config := &kube.Config{KubeConfig: "/home/user/.kube/config"}

	initializer := provider.NewErrorSSHProviderInitializer(fmt.Errorf("kube client is not used over ssh"))
	runner, err := provider.GetRunnerInterface(ctx, config, sett, initializer)
	if err != nil {
		log.Fatal(err)
	}

	kubeProvider := provider.NewDefaultKubeProvider(sett, config, runner)
	defer func() {
		if err := kubeProvider.Cleanup(ctx); err != nil {
			sett.Logger().Error(fmt.Sprintf("cleanup kube provider: %v", err))
		}
	}()

	client, err := kubeProvider.Client(ctx)
	if err != nil {
		log.Fatal(err)
	}

	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("got %d nodes\n", len(nodes.Items))
}
```

### Combining SSH and Kubernetes providers

When a `KubeProvider` should be able to reach the API over SSH (`kube.Config.OverSSH()` is true), give
`GetRunnerInterface` a real `SSHProviderInitializer` instead of the error one, so it can start kube-proxy
over the SSH client:

```go
sshConfig, err := sshFlags.ExtractConfig(os.Args[1:])
if err != nil {
	return err
}

sshProvider := provider.NewDefaultSSHProvider(sett, sshConfig, provider.SSHClientWithStartAfterCreate(true))
sshInitializer := provider.NewSimpleSSHProviderInitializer(sshProvider)

kubeConfig, err := kubeFlags.ExtractConfig(os.Args[1:]...)
if err != nil {
	return err
}

runner, err := provider.GetRunnerInterface(ctx, kubeConfig, sett, sshInitializer)
if err != nil {
	return err
}

kubeProvider := provider.NewDefaultKubeProvider(sett, kubeConfig, runner)
// Client() calls the kube API over the SSH client's kube-proxy and reconnects
// automatically if the SSH provider's client is switched.
```

This is the pattern used in production by [dhctl](https://github.com/deckhouse/deckhouse), which wraps
both providers behind a single `GetProviders(ctx, params, opts...)` call so callers get an
`SSHProviderInitializer` and a `KubeProvider` from one entry point, with an options pattern
(`WithConnectionConfig`, `WithKubeConfig`, `WithRequiredKubeProvider`, ...) to control how each is
constructed for a given command.

### Flags parsing and cobra integration

Because we are using the [pflag](https://github.com/spf13/pflag) library, `kube.FlagsParser` and
`sshconfig.FlagsParser` compose with `cobra.Command.PersistentFlags()`. See [ParseFlags](#parseflags)
above and the full [cobra example](./examples/cobra) for `kube`, `ssh`, and `ssh-additional` subcommands.

## Testing

We added a lot of unit and integration tests. To run the full test suite use the command:

```bash
make test
```

But the full test suite requires a long time (currently about 30 minutes), because we run SSH and kind containers
for integration testing and tests have long sleeps to prove logic.

If you do not need to run integration tests you can use:

```bash
make test/no-integration
```

In pull requests on GitHub you can use the `test/no-integration` label.

For a full cleanup of test resources you can use the command:

```bash
make clean/test
```

It will remove all containers and the kind cluster and also remove all temp files.
