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

	createValidConfigAndPassArg := func(t *testing.T, ts *test) string {
		path := createValidTestConfig(t, ts.test)
		ts.arguments = append(ts.arguments, fmt.Sprintf("--kubeconfig=%s", path))
		return path
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
			name: "kubeconfig path flag",

			arguments: []string{},

			before: func(t *testing.T, ts *test) {
				path := createValidConfigAndPassArg(t, ts)
				ts.expected.KubeConfig = path
			},

			hasErrorContains:      "",
			hasParseErrorContains: "",

			expected: &Config{},
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

			err = fset.Parse(testCase.arguments)
			if assertError(t, err, testCase.hasParseErrorContains) {
				return
			}

			config, err := parser.ExtractConfigAfterParse(flags)
			if assertError(t, err, testCase.hasParseErrorContains) {
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

func (p *testHelpParser) InitFlags(flagSet *flag.FlagSet) error {
	_, err := p.parser.InitFlags(flagSet)
	return err
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
