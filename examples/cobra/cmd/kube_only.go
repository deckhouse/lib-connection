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
	"time"

	"github.com/deckhouse/lib-connection/examples/cobra/flag"
	"github.com/deckhouse/lib-connection/pkg/kube"
	"github.com/deckhouse/lib-connection/pkg/provider"
	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-dhctl/pkg/retry"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type SettingsProvider func() settings.Settings

func AppendKubeCommand(settProvider SettingsProvider, rootCmd *cobra.Command) (*cobra.Command, error) {
	printWarning := false

	parser := kube.NewFlagsParser(settProvider())

	kubeCmd := &cobra.Command{
		Use:   "kube-only",
		Short: "Run kube example without ssh.",
		Long:  "Run kube example without ssh.",
	}

	if rootCmd != nil {
		rootCmd.AddCommand(kubeCmd)
	}

	flagSet := kubeCmd.PersistentFlags()

	flagSet.BoolVar(&printWarning, "print-warning", false, "Print warning messages.")

	flags, err := parser.InitFlags(flagSet)
	if err != nil {
		return nil, err
	}

	combine := &flag.KubeFlags{
		Flags:  flags,
		Parser: parser,
	}

	kubeCmd.RunE = func(cmd *cobra.Command, args []string) error {
		err := runKube(&runKubeParams{
			flags:        combine,
			printWarn:    &printWarning,
			settProvider: settProvider,
			cmd:          cmd,
			commandArgs:  args,
		})

		if err != nil {
			cmd.SilenceUsage = true
		}

		return err
	}

	return kubeCmd, nil
}

type runKubeParams struct {
	flags        *flag.KubeFlags
	printWarn    *bool
	settProvider SettingsProvider
	cmd          *cobra.Command
	commandArgs  []string
}

func runKube(params *runKubeParams) error {
	sett := params.settProvider()

	// you should call flags.Parse because flags uses copy
	if err := params.flags.Flags.Parse(params.commandArgs); err != nil {
		return fmt.Errorf("cannot parse kube flags: %w", err)
	}

	conf, err := params.flags.Parser.ExtractConfigAfterParse(params.flags.Flags)
	if err != nil {
		return fmt.Errorf("failed to extract kube provider config: %v", err)
	}

	providerErr := fmt.Errorf("should not use over ssh")
	runner, err := provider.GetRunnerInterface(conf, sett, provider.NewErrorSSHProvider(providerErr))
	kubeProvider := provider.NewDefaultKubeProvider(sett, conf, runner)

	ctx := params.cmd.Context()

	defer func() {
		logger := sett.Logger()

		if err := kubeProvider.Cleanup(ctx); err != nil {
			logger.ErrorF("Failed to cleanup kube provider: %v", err)
			return
		}

		logger.InfoF("kube provider cleaned up successfully")
	}()

	if *params.printWarn {
		sett.Logger().WarnF("WARNING: printing warnings flag set")
	}

	if err != nil {
		return fmt.Errorf("failed to setup kube client", err)
	}

	if err := getNodes(ctx, sett, kubeProvider); err != nil {
		return fmt.Errorf("failed to get nodes: %w", err)
	}

	return nil
}

func getNodes(ctx context.Context, sett settings.Settings, kubeProvider *provider.DefaultKubeProvider) error {
	loopParams := retry.NewEmptyParams(
		retry.WithName("Getting nodes"),
		retry.WithAttempts(5),
		retry.WithWait(2*time.Second),
		retry.WithLogger(sett.Logger()),
	)

	return retry.NewLoopWithParams(loopParams).RunContext(ctx, func() error {
		client, err := kubeProvider.Client(ctx)
		if err != nil {
			return fmt.Errorf("cannot extract kube client: %w", err)
		}

		nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("cannot list kube nodes: %w", err)
		}

		sett.Logger().InfoF("Got kube nodes: %d\n", len(nodes.Items))

		for _, node := range nodes.Items {
			sett.Logger().InfoF("\t%s\n", node.Name)
		}

		return nil
	})
}
