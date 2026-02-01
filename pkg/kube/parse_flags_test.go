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

package kube

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	flag "github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/tools/clientcmd/api/latest"
	"sigs.k8s.io/yaml"

	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/tests"
)

func TestParseFlags(t *testing.T) {
	type test struct {
		name string

		arguments []string

		envsPrefix string
		envs       map[string]string

		hasErrorContains      string
		hasParseErrorContains string

		expected *Config
		before   func(*testing.T, *test)
		test     *tests.Test
	}

	appendKubeConfigArgument := func(ts *test, path string) {
		ts.arguments = append(ts.arguments, fmt.Sprintf("--kubeconfig=%s", path))
	}

	createValidConfigAndPassArg := func(t *testing.T, ts *test) {
		path := createValidTestConfig(t, ts.test)
		appendKubeConfigArgument(ts, path)
		if ts.expected != nil {
			ts.expected.KubeConfig = path
		}
	}

	cases := []test{
		{
			name: "no arguments provide empty config",

			arguments: nil,

			hasErrorContains:      "",
			hasParseErrorContains: "",

			expected: &Config{},
		},

		{
			name: "in cluster config",

			arguments: []string{
				"--kube-client-from-cluster",
			},

			hasErrorContains:      "",
			hasParseErrorContains: "",

			expected: &Config{
				KubeConfigInCluster: true,
			},
		},

		{
			name: "unknown flags should skip",

			arguments: []string{
				"--ssh-extra-args=a,b",
			},

			before: createValidConfigAndPassArg,

			hasErrorContains:      "",
			hasParseErrorContains: "",

			expected: &Config{},
		},

		{
			name: "kubeconfig path flag",

			arguments: []string{},

			before: createValidConfigAndPassArg,

			hasErrorContains:      "",
			hasParseErrorContains: "",

			expected: &Config{},
		},

		{
			name: "kubeconfig with valid context",

			arguments: []string{
				"--kubeconfig-context=clean",
			},

			before: createValidConfigAndPassArg,

			hasErrorContains:      "",
			hasParseErrorContains: "",

			expected: &Config{
				KubeConfigContext: "clean",
			},
		},

		{
			name: "kubeconfig and in cluster client passed both",

			arguments: []string{
				"--kube-client-from-cluster",
			},

			before: createValidConfigAndPassArg,

			hasErrorContains:      "Cannot use both --kubeconfig and --kube-client-from-cluster or envs KUBE_CONFIG and KUBE_CLIENT_FROM_CLUSTER at the same time",
			hasParseErrorContains: "",
		},

		{
			name: "kubeconfig and incorrect context",

			arguments: []string{
				"--kubeconfig-context=not-exists",
			},

			before: createValidConfigAndPassArg,

			hasErrorContains:      "Cannot find context 'not-exists' in kube config",
			hasParseErrorContains: "",
		},

		{
			name: "pass context without kubeconfig",

			arguments: []string{
				"--kubeconfig-context=not-exists",
			},

			hasErrorContains:      "Pass context flag --kubeconfig-context without kubeconfig path --kubeconfig",
			hasParseErrorContains: "",
		},

		{
			name: "not exists kubeconfig",

			before: func(t *testing.T, ts *test) {
				appendKubeConfigArgument(ts, "/tmp/not-exsists-2dfr.yaml")
			},

			hasErrorContains:      "Cannot get kube config file info for /tmp/not-exsists-2dfr.yaml",
			hasParseErrorContains: "",
		},

		{
			name: "kubeconfig as dir",

			before: func(t *testing.T, ts *test) {
				dir := ts.test.MustMkSubDirs(t, "kube-config-as-dir")
				appendKubeConfigArgument(ts, dir)
			},

			hasErrorContains:      "should be regular file",
			hasParseErrorContains: "",
		},
	}

	assertError := func(t *testing.T, err error, errorContains string) bool {
		if errorContains != "" {
			require.Error(t, err, "should parse error")
			require.Contains(t, err.Error(), errorContains, "should parse error contains")
			return true
		}

		require.NoError(t, err, "parse flags")

		return false
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			tst := tests.ShouldNewTest(t, testCase.name)
			sett := tst.Settings()

			testCase.test = tst

			if testCase.before != nil {
				testCase.before(t, &testCase)
			}

			parser := NewFlagsParser(sett)
			parser.WithEnvsPrefix(testCase.envsPrefix)
			if len(testCase.envs) > 0 {
				parser.WithEnvsLookup(func(name string) (string, bool) {
					val, ok := testCase.envs[name]
					return val, ok
				})
			}

			flagSetName := strings.ReplaceAll(testCase.name, " ", "-")
			flagSetName = strings.ReplaceAll(flagSetName, ":", "-")
			flagSetName = "test-parse" + flagSetName

			fset := flag.NewFlagSet(flagSetName, flag.ContinueOnError)
			flags, err := parser.InitFlags(fset)
			require.NoError(t, err, "init flags")

			err = flags.Parse(testCase.arguments)
			if assertError(t, err, testCase.hasParseErrorContains) {
				return
			}

			config, err := parser.ExtractConfigAfterParse(flags)
			if assertError(t, err, testCase.hasErrorContains) {
				return
			}

			require.Equal(t, testCase.expected, config, "should valid config")
		})
	}

	t.Run("ParseFlagsAndExtractConfig", func(t *testing.T) {
		t.Run("with args and no FlagSet", func(t *testing.T) {
			assertParseAndExtract(t, assertParseAndExtractParams{
				envsPrefix: "ARGS_NO_FLAG_SET",
				arguments: []string{
					"--kube-client-from-cluster",
				},
				expected: &Config{
					KubeConfigInCluster: true,
				},
			})
		})

		t.Run("with args and with FlagSet", func(t *testing.T) {
			flagSet := newParseFlagsAndExtractConfigFlagSet("test-connection-flagset")

			args := []string{
				"--kube-client-from-cluster",
			}

			args = append(args, flagSet.additionalArguments()...)

			assertParseAndExtract(t, assertParseAndExtractParams{
				envsPrefix: "ARGS_FLAG_SET",
				arguments:  args,
				flagSet:    flagSet.flagSet,
				expected: &Config{
					KubeConfigInCluster: true,
				},
			})

			flagSet.assertAdditionalFlagsParsed(t)
		})

		t.Run("without args and with FlagSet", func(t *testing.T) {
			tst := tests.ShouldNewTest(t, t.Name())
			kubeConfigPath := createValidTestConfig(t, tst)

			args := []string{
				fmt.Sprintf("--kubeconfig=%s", kubeConfigPath),
				"--kubeconfig-context=clean",
			}

			// use subtest for safe rewrite os.Args
			// we cannot use pass args with -args because we can run test from IDE
			//nolint:gosec
			cmd := exec.Command(os.Args[0], "-test.run=TestParseKubeFlagsAndExtractConfigNoArgs")
			cmd.Env = append(
				os.Environ(),
				fmt.Sprintf("TEST_NO_ARGS_KUBE=%s",
					strings.Join(args, " "),
				),
			)

			output, err := cmd.CombinedOutput()
			require.NoError(
				t,
				err,
				"TestParseKubeFlagsAndExtractConfigNoArgs should run without error: %s",
				string(output),
			)

			tst.GetLogger().InfoF("Got output from TestParseFlagsAndExtractConfigNoArgs:\n%s", string(output))
		})
	})
}

func TestParseFlagsNoInitialize(t *testing.T) {
	getParser := func(t *testing.T) *FlagsParser {
		test := tests.ShouldNewTest(t, tests.Name(t))
		return NewFlagsParser(test.Settings())
	}

	assertError := func(t *testing.T, config *Config, err error, contains string) {
		require.Error(t, err, "should not have an error")
		require.Contains(t, err.Error(), contains)
		require.Nil(t, config)
	}

	t.Run("Extract without initialize", func(t *testing.T) {
		flags := &Flags{
			Config: Config{
				KubeConfigContext: "clean",
				KubeConfig:        "/tmp/not-exsists-5jfr.yaml",
			},
		}

		parser := getParser(t)
		config, err := parser.ExtractConfigAfterParse(flags)
		assertError(t, config, err, "Call InitFlags first and pass Flags from result of InitFlags")
	})

	t.Run("Extract from no parsed flagset", func(t *testing.T) {
		flagSet := flag.NewFlagSet("no-parsed", flag.ContinueOnError)
		parser := getParser(t)
		flags, err := parser.InitFlags(flagSet)
		require.NoError(t, err, "init flags should initialized")
		config, err := parser.ExtractConfigAfterParse(flags)
		assertError(t, config, err, "flagsSet is not parsed. Call flag.Parse or flag.FlagSet.Parse before extract config")
	})

	t.Run("Init config if flags already parsed", func(t *testing.T) {
		flagSet := newParseFlagsAndExtractConfigFlagSet("already-parsed")
		flagSet.parseOnlyAdditional(t)

		parser := getParser(t)
		flags, err := parser.InitFlags(flagSet.flagSet)
		assertError(t, nil, err, "Flags already parsed")
		require.Nil(t, flags, "flags should be nil")
	})

	t.Run("ParseFlagsAndExtractConfig if flags already parsed", func(t *testing.T) {
		flagSet := newParseFlagsAndExtractConfigFlagSet("already-parsed-parse-extract")
		flagSet.parseOnlyAdditional(t)

		parser := getParser(t)
		config, err := parser.ParseFlagsAndExtractConfig(make([]string, 0), flagSet.flagSet)
		assertError(t, config, err, "Flags already parsed")
	})
}

func TestParseKubeFlagsAndExtractConfigNoArgs(t *testing.T) {
	argsStr, ok := os.LookupEnv("TEST_NO_ARGS_KUBE")
	argsStr = strings.TrimSpace(argsStr)

	if !ok || argsStr == "" {
		t.Skip("Run TestParseKubeFlagsAndExtractConfigNoArgs directly")
	}

	// split by -- for safe process arguments with spaces
	argsParts := strings.Split(argsStr, "--")
	require.NotEmpty(t, argsParts, "args should not be empty")

	testArgs := make([]string, 0, len(argsParts))
	for _, arg := range argsParts {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			continue
		}

		if !strings.HasPrefix(arg, "--") {
			arg = fmt.Sprintf("--%s", arg)
		}

		testArgs = append(testArgs, arg)
	}

	const kubeConfigArg = "--kubeconfig="

	kubeConfigPath := ""

	for _, arg := range testArgs {
		if strings.HasPrefix(arg, kubeConfigArg) {
			kubeConfigPath = strings.TrimPrefix(arg, kubeConfigArg)
			kubeConfigPath = strings.TrimSpace(kubeConfigPath)
			break
		}
	}

	require.NotEmpty(
		t,
		kubeConfigPath,
		"kubeconfig path should present in args: %v",
		strings.Join(testArgs, " "),
	)

	fmt.Printf("os.Args after parse: %s\n", strings.Join(testArgs, " "))

	flagSet := newParseFlagsAndExtractConfigFlagSet("test-connection-without-args")

	require.Len(t, flagSet.arguments, 1, "should add additional arguments")

	oldArgs := os.Args
	t.Cleanup(func() {
		os.Args = oldArgs
	})

	withAdditional := []string{
		os.Args[0],
		flagSet.arguments[0],
	}

	withAdditional = append(withAdditional, testArgs...)
	os.Args = withAdditional

	assertParseAndExtract(t, assertParseAndExtractParams{
		envsPrefix: "NO_ARGS",
		flagSet:    flagSet.flagSet,
		expected: &Config{
			KubeConfig:        kubeConfigPath,
			KubeConfigContext: "clean",
		},
	})

	flagSet.assertAdditionalFlagsParsed(t)
}

func TestParseFlagsHelp(t *testing.T) {
	tests.AssertParseFlagsHelp(t, tests.AssertParseFlagsHelpParams{
		ExpectedFlags: 3,
		Name:          "kube-flags",
		Provider: func(sett settings.Settings, envsPrefix string) tests.TestFlagsParser {
			parser := NewFlagsParser(sett)
			parser.WithEnvsPrefix(envsPrefix)

			return &testHelpParser{parser: parser}
		},
	})
}

type testHelpParser struct {
	parser *FlagsParser
}

func (p *testHelpParser) InitFlags(flagSet *flag.FlagSet) (*flag.FlagSet, error) {
	flags, err := p.parser.InitFlags(flagSet)
	if err != nil {
		return nil, err
	}

	return flags.baseFlags.FlagSet(), err
}

func createValidTestConfig(t *testing.T, test *tests.Test) string {
	const (
		server = "https://anything.com:8080"
		token  = "the-token"
	)

	config := clientcmdapi.NewConfig()
	config.APIVersion = "v1"
	config.Kind = "Config"

	config.Clusters["clean"] = &clientcmdapi.Cluster{
		Server: server,
	}
	config.AuthInfos["clean"] = &clientcmdapi.AuthInfo{
		Token: token,
	}
	config.Contexts["clean"] = &clientcmdapi.Context{
		Cluster:  "clean",
		AuthInfo: "clean",
	}
	config.CurrentContext = "clean"

	json, err := runtime.Encode(latest.Codec, config)
	require.NoError(t, err, "encode json")

	content, err := yaml.JSONToYAML(json)
	require.NoError(t, err, "marshal kube config")

	return test.MustCreateTmpFile(t, string(content), false, "kubeconfig.yaml")
}

type parseFlagsAndExtractConfigFlagSet struct {
	arguments       []string
	additionalParam string
	flagSet         *flag.FlagSet
}

func newParseFlagsAndExtractConfigFlagSet(name string) *parseFlagsAndExtractConfigFlagSet {
	res := &parseFlagsAndExtractConfigFlagSet{}

	flagSet := flag.NewFlagSet(name, flag.ContinueOnError)
	flagSet.StringVar(&res.additionalParam, "my-param", "", "test argument")

	res.flagSet = flagSet

	res.arguments = append(res.arguments, res.additionalArguments()...)

	return res
}

func (s *parseFlagsAndExtractConfigFlagSet) additionalArguments() []string {
	return []string{
		"--my-param=val",
	}
}

func (s *parseFlagsAndExtractConfigFlagSet) assertAdditionalFlagsParsed(t *testing.T) {
	require.Equal(t, s.additionalParam, "val", "should parse additional argument")
}

func (s *parseFlagsAndExtractConfigFlagSet) parseOnlyAdditional(t *testing.T) {
	err := s.flagSet.Parse(s.additionalArguments())
	require.NoError(t, err, "should parse only additional flags")
	s.assertAdditionalFlagsParsed(t)
}

type assertParseAndExtractParams struct {
	envsPrefix string
	arguments  []string
	flagSet    *flag.FlagSet
	expected   *Config
}

func assertParseAndExtract(t *testing.T, params assertParseAndExtractParams) {
	tst := tests.ShouldNewTest(t, t.Name())

	parser := NewFlagsParser(tst.Settings())
	parser.WithEnvsPrefix(params.envsPrefix)

	config, err := parser.ParseFlagsAndExtractConfig(params.arguments, params.flagSet)
	require.NoError(t, err, "should parse and extract")

	require.Equal(t, params.expected, config, "config should be equal")
}
