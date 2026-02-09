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

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/deckhouse/lib-connection/examples/cobra/cmd"
	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-dhctl/pkg/log"
	"github.com/spf13/cobra"
)

type CommandProvider func(cmd.SettingsProvider, *cobra.Command) (*cobra.Command, error)

type command struct {
	shouldContainsInHelp []string
	provider             CommandProvider
}

func main() {
	const envsPrefix = "COBRA"

	cobra.EnableTraverseRunHooks = true

	rootCmd := &cobra.Command{
		Use:   "cobra-example",
		Short: "Run cobra example.",
		Long:  "Run cobra example.",
	}

	global := &globalArgs{
		loggerType: string(log.Pretty),
		tmpDir:     filepath.Join(os.TempDir(), "cobra-example"),
	}

	rootCmd.PersistentFlags().StringVar(&global.loggerType, "log-type", global.loggerType, "log type")
	rootCmd.PersistentFlags().StringVar(&global.tmpDir, "tmp-dir", global.tmpDir, "Temp directory")

	isDebug := os.Getenv(fmt.Sprintf("%s_DEBUG", envsPrefix)) != ""

	logger := log.NewPrettyLogger(log.LoggerOptions{
		IsDebug: isDebug,
	})

	sett := settings.NewBaseProviders(settings.ProviderParams{
		LoggerProvider: log.SimpleLoggerProvider(logger),
		IsDebug:        isDebug,
		EnvsPrefix:     envsPrefix,
	})

	rootCmd.PersistentPreRunE = func(*cobra.Command, []string) error {
		newSett, err := initSettings(sett, global)
		if err != nil {
			return err
		}

		sett = newSett

		return nil
	}

	settingsProvider := func() settings.Settings {
		return sett
	}

	subCommands := map[string]command{
		"kube": {
			provider: cmd.AppendKubeCommand,
			shouldContainsInHelp: []string{
				// global flags
				"--log-type",
				// kube flags
				" --kube-client-from-cluster",
				// envs prefix
				envsPrefix + "_",
			},
		},
		"ssh": {
			provider: cmd.AppendSSHCommand,
			shouldContainsInHelp: []string{
				// global flags
				"--tmp-dir",
				// kube flags
				"--kubeconfig-context",
				// ssh flags
				"--ssh-legacy-mode",
				// envs prefix
				envsPrefix + "_",
			},
		},
	}

	for name, c := range subCommands {
		cc, err := c.provider(settingsProvider, rootCmd)
		if err != nil {
			sett.Logger().ErrorF("Failed to append command %s: %s", name, err)
			os.Exit(1)
			return
		}

		// unnecessary check
		help := cc.UsageString()
		for _, h := range c.shouldContainsInHelp {
			if !strings.Contains(help, h) {
				sett.Logger().ErrorF("Failed to append command %s, help should contains %s", name, h)
				os.Exit(1)
			}
		}
	}

	rootCmd.SilenceErrors = true
	rootCmd.TraverseChildren = true

	if err := rootCmd.Execute(); err != nil {
		sett.Logger().ErrorF("Failed to execute command: %s", err)
		os.Exit(1)
	}
}

type globalArgs struct {
	loggerType string
	tmpDir     string
}

func initSettings(sett *settings.BaseProviders, args *globalArgs) (*settings.BaseProviders, error) {
	tmpDir := args.tmpDir

	sett.Logger().InfoF("Got tmp dir: %s", tmpDir)
	sett.Logger().InfoF("Got logger type: %s", args.loggerType)

	if tmpDir == "" || tmpDir == "/" {
		return nil, fmt.Errorf("pass incorect tmp dir '%s'", tmpDir)
	}

	if err := os.MkdirAll(tmpDir, os.ModePerm); err != nil {
		sett.Logger().ErrorF("failed to create tmp dir %s: %v", tmpDir, err)
		return nil, err
	}

	loggerFromArgs, err := log.NewLogger(log.Type(args.loggerType), sett.IsDebug())
	if err != nil {
		return nil, err
	}

	sett = sett.Clone(
		settings.CloneWithLoggerProvider(log.SimpleLoggerProvider(loggerFromArgs)),
		settings.CloneWithTmpDir(tmpDir),
	)

	cobra.OnFinalize(func() {
		tmpDir = sett.TmpDir()
		logger := sett.Logger()

		if err := os.RemoveAll(tmpDir); err != nil {
			logger.ErrorF("Failed to remove tmp dir %s: %v", tmpDir, err)
			return
		}

		logger.InfoF("Tmp dir: '%s' removed", tmpDir)
	})

	return sett, nil
}
