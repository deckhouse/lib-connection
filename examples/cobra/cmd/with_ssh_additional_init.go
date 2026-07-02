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

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/name212/govalue"
	"github.com/spf13/cobra"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/kube"
	"github.com/deckhouse/lib-connection/pkg/provider"
	"github.com/deckhouse/lib-connection/pkg/settings"
	sshconfig "github.com/deckhouse/lib-connection/pkg/ssh/config"
)

func AppendSSHAdditionalCommand(settProvider SettingsProvider, rootCmd *cobra.Command) (*cobra.Command, error) {
	sshCmd := &cobra.Command{
		Use:   "ssh-additional",
		Short: "Run example ssh with additional initialization",
		Long:  "Run example ssh with additional initialization",
	}

	// you should add cmd to parent
	if rootCmd != nil {
		rootCmd.AddCommand(sshCmd)
	}

	// example of usage another flags in command is allowed
	// you should use PersistentFlags for getting flags from parent
	flagSet := sshCmd.PersistentFlags()

	// default initialization way for flags

	kubeParser := kube.NewFlagsParser(settProvider())
	kubeFlags, err := kubeParser.InitFlags(flagSet)
	if err != nil {
		return nil, err
	}

	sshParser := sshconfig.NewFlagsParser(settProvider())
	sshFlags, err := sshParser.InitFlags(flagSet)
	if err != nil {
		return nil, err
	}

	// flags should pass to handler
	// because in handler we have all parsed keys
	// and we should extract configs in handler

	sshCmd.RunE = func(cmd *cobra.Command, args []string) error {
		err := runSSHAdditional(&runSSHParams{
			sshFlags:     sshFlags,
			kubeFlags:    kubeFlags,
			settProvider: settProvider,
			cmd:          cmd,
			commandArgs:  args,
		})

		if err != nil {
			cmd.SilenceUsage = true
		}

		return err
	}

	return sshCmd, nil
}

func runSSHAdditional(params *runSSHParams) error {
	ctx := params.cmd.Context()

	sett := params.settProvider()

	kubeConfig, err := params.kubeFlags.ExtractConfig(params.commandArgs...)
	if err != nil {
		return fmt.Errorf("cannot parse kube config: %w", err)
	}

	consumer := newAdditionalProvidersConsumer(params, kubeConfig)

	// please clean up providers in the end of handler
	defer func() {
		consumer.Cleanup(ctx)
	}()

	return doSSHAdditional(ctx, sett, consumer)
}

type providersConsumer interface {
	provider.SSHProviderInitializerWithCleanup
	provider.KubeProviderInitializerWithCleanup
	SetSSHHost(h string)
}

func doSSHAdditional(ctx context.Context, sett settings.Settings, consumer providersConsumer) error {
	hostFromEnv := os.Getenv("SSH_HOST_CONNECT")
	if hostFromEnv != "" {
		consumer.SetSSHHost(hostFromEnv)
	}

	kubeProvider, err := consumer.GetKubeProvider(ctx)
	if err != nil {
		return fmt.Errorf("Cannot initialize kube providder")
	}

	if err := getNodes(ctx, sett, kubeProvider); err != nil {
		return fmt.Errorf("failed to get nodes: %w", err)
	}

	sshProvider, err := consumer.GetSSHProvider(ctx)
	if errors.Is(err, errNotPassedSSHHost) {
		sett.Logger().WarnContext(ctx, "SSH host not passed. Skip run ssh command. Pass SSH_HOST_CONNECT env")
		return nil
	}

	sshClient, err := sshProvider.Client(ctx)
	if err != nil {
		return fmt.Errorf("failed to get ssh client")
	}

	if err := doSSHCommand(ctx, sshClient); err != nil {
		return fmt.Errorf("fail to run ssh command: %w", err)
	}

	sett.Logger().InfoContext(ctx, "SSH command succeeded")

	return nil
}

type additionalProvidersConsumer struct {
	kubeConfig *kube.Config
	sshFlags   *sshconfig.Flags
	args       []string

	sett settings.Settings

	sshProvider  connection.SSHProvider
	kubeProvider connection.KubeProvider

	sshHost string
}

func newAdditionalProvidersConsumer(params *runSSHParams, kubeConfig *kube.Config) *additionalProvidersConsumer {
	return &additionalProvidersConsumer{
		kubeConfig: kubeConfig,
		sshFlags:   params.sshFlags,
		args:       params.commandArgs,
		sett:       params.settProvider(),
	}
}

func (i *additionalProvidersConsumer) GetKubeProvider(ctx context.Context) (connection.KubeProvider, error) {
	if govalue.NotNil(i.kubeProvider) {
		return i.kubeProvider, nil
	}

	runner, err := provider.GetRunnerInterface(ctx, i.kubeConfig, i.sett, i)
	if err != nil {
		return nil, fmt.Errorf("Cannot get runner for kube provider: %w", err)
	}

	i.kubeProvider = provider.NewDefaultKubeProvider(i.sett, i.kubeConfig, runner)

	return i.kubeProvider, nil
}

var errNotPassedSSHHost = fmt.Errorf("ssh host not passed")

func (i *additionalProvidersConsumer) GetSSHProvider(_ context.Context) (connection.SSHProvider, error) {
	if govalue.NotNil(i.sshProvider) {
		return i.sshProvider, nil
	}

	sshConfig, err := i.sshFlags.ExtractConfig(i.args)
	if err != nil {
		return nil, fmt.Errorf("cannot parse ssh config: %w", err)
	}

	if len(sshConfig.Hosts) == 0 {
		if i.sshHost == "" {
			return nil, errNotPassedSSHHost
		}

		sshConfig.Hosts = append(sshConfig.Hosts, sshconfig.Host{
			Host: i.sshHost,
		})
	}

	i.sshProvider = provider.NewDefaultSSHProvider(i.sett, sshConfig, provider.SSHClientWithStartAfterCreate(true))

	return i.sshProvider, nil
}

func (i *additionalProvidersConsumer) Cleanup(ctx context.Context) error {
	logger := i.sett.Logger()

	if govalue.NotNil(i.kubeProvider) {
		if err := i.kubeProvider.Cleanup(ctx); err != nil {
			logger.ErrorContext(ctx, fmt.Sprintf("Failed to cleanup kube provider: %v", err))
		} else {
			logger.InfoContext(ctx, "Kube provider cleaned up successfully")

		}
	}

	if govalue.NotNil(i.sshProvider) {
		if err := i.sshProvider.Cleanup(ctx); err != nil {
			logger.ErrorContext(ctx, fmt.Sprintf("Failed to cleanup SSH provider: %v", err))
		} else {
			logger.InfoContext(ctx, "SSH provider cleaned up successfully")
		}
	}

	i.sshProvider = nil
	i.kubeProvider = nil

	return nil
}

func (i *additionalProvidersConsumer) SetSSHHost(h string) {
	i.sshHost = h
}
