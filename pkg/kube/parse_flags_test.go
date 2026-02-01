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
