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
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/kube"
	"github.com/deckhouse/lib-connection/pkg/provider"
	sshconfig "github.com/deckhouse/lib-connection/pkg/ssh/config"
)

func AppendSSHCommand(settProvider SettingsProvider, rootCmd *cobra.Command) (*cobra.Command, error) {
	sshCmd := &cobra.Command{
		Use:   "ssh",
		Short: "Run example ssh",
		Long:  "Run example ssh",
	}

	// you should add cmd to parent
	if rootCmd != nil {
		rootCmd.AddCommand(sshCmd)
	}

	// example of usage another flags in command is allowed
	// you should use PersistentFlags for getting flags from parent
	flagSet := sshCmd.PersistentFlags()
	useStandaloneKube := false
	flagSet.BoolVar(&useStandaloneKube, "use-standalone-kube", false, "Use provided kube settings not over ssh")

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
		err := runSSH(&runSSHParams{
			sshFlags:          sshFlags,
			kubeFlags:         kubeFlags,
			useStandaloneKube: &useStandaloneKube,
			settProvider:      settProvider,
			cmd:               cmd,
			commandArgs:       args,
		})

		if err != nil {
			cmd.SilenceUsage = true
		}

		return err
	}

	return sshCmd, nil
}

type runSSHParams struct {
	kubeFlags         *kube.Flags
	sshFlags          *sshconfig.Flags
	useStandaloneKube *bool
	settProvider      SettingsProvider
	cmd               *cobra.Command
	commandArgs       []string
}

func runSSH(params *runSSHParams) error {
	ctx := params.cmd.Context()

	sett := params.settProvider()

	kubeConfig, err := params.kubeFlags.ExtractConfig(params.commandArgs...)
	if err != nil {
		return fmt.Errorf("cannot parse kube config: %w", err)
	}

	var sshOpts []sshconfig.ValidateOption
	if kubeConfig.OverSSH() {
		sshOpts = append(sshOpts, sshconfig.ParseWithRequiredSSHHost(true))
	}

	sshConfig, err := params.sshFlags.ExtractConfig(params.commandArgs, sshOpts...)
	if err != nil {
		return fmt.Errorf("cannot parse ssh config: %w", err)
	}

	sshProvider := provider.NewDefaultSSHProvider(sett, sshConfig, provider.SSHClientWithStartAfterCreate(true))

	// please clean up providers in the end of handler
	defer func() {
		logger := sett.Logger()

		if err := sshProvider.Cleanup(ctx); err != nil {
			logger.ErrorContext(ctx, fmt.Sprintf("Failed to cleanup ssh provider: %v", err))
			return
		}

		logger.InfoContext(ctx, "SSH provider cleaned up successfully")
	}()

	// example logic if you can use over ssh client and not
	// in one handler
	// also you can track if you should use over ssh connection
	// with kubeConfig.OverSSH() method
	// but keep in mind, that your handler can use connection to kube API
	// with kubeconfig, but also your handler can do some actions over ssh
	var sshProviderForKube connection.SSHProvider = sshProvider
	if *params.useStandaloneKube {
		providerErr := fmt.Errorf("should not use over ssh")
		sshProviderForKube = provider.NewErrorSSHProvider(providerErr)
	}

	initializer := provider.NewSimpleSSHProviderInitializer(sshProviderForKube)

	runner, err := provider.GetRunnerInterface(ctx, kubeConfig, sett, initializer)
	kubeProvider := provider.NewDefaultKubeProvider(sett, kubeConfig, runner)

	// please clean up providers in the end of handler
	defer func() {
		logger := sett.Logger()

		if err := kubeProvider.Cleanup(ctx); err != nil {
			logger.ErrorContext(ctx, fmt.Sprintf("Failed to cleanup kube provider: %v", err))
			return
		}

		logger.InfoContext(ctx, "kube provider cleaned up successfully")
	}()

	if err != nil {
		return fmt.Errorf("failed to setup kube client: %w", err)
	}

	if err := getNodes(ctx, sett, kubeProvider); err != nil {
		return fmt.Errorf("failed to get nodes: %w", err)
	}

	notUseSSH := os.Getenv("NOT_USE_SSH")
	if notUseSSH != "" {
		sett.Logger().InfoContext(ctx, "Not use ssh passed")
		return nil
	}

	sshClient, err := sshProvider.Client(ctx)
	if err != nil {
		return fmt.Errorf("failed to setup ssh client: %w", err)
	}

	if err := doSSHCommand(ctx, sshClient); err != nil {
		return err
	}

	sett.Logger().InfoContext(ctx, "SSH command succeeded")

	return nil
}

func doSSHCommand(ctx context.Context, sshClient connection.SSHClient) error {
	const echoStr = "SUCCESS"

	cmd := sshClient.Command("echo", "-n", echoStr)
	cmd.Sudo(ctx)
	strOut, _, err := cmd.Output(ctx)
	if err != nil {
		return fmt.Errorf("failed to run echo command: %w", err)
	}

	if !strings.Contains(string(strOut), echoStr) {
		return fmt.Errorf("failed to run echo command, got output: %s", string(strOut))
	}

	return nil
}
