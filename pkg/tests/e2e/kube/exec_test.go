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

package kube_test

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/retry"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/kube"
	"github.com/deckhouse/lib-connection/pkg/provider"
	"github.com/deckhouse/lib-connection/pkg/tests"
	kind "github.com/deckhouse/lib-connection/pkg/tests/e2e/kube/kind"
)

func TestKubeExec(t *testing.T) {
	execTest := tests.ShouldNewIntegrationTest(
		t,
		t.Name(),
		tests.TestWithParallelRun(true),
	)

	kindCluster := kind.CreateKINDCluster(t, &kind.KINDClusterCreateParams{
		Test:                                execTest,
		ClusterName:                         "exec-in-pod",
		NoPrepareLocalKubectlInSSHContainer: true,
	})

	kindCluster.RegisterCleanup(t)

	kubeProvider := getKubeProviderForExec(t, execTest, kindCluster)

	pythonImage := os.Getenv("TESTS_PYTHON_IMAGE")
	if pythonImage == "" {
		pythonImage = "registry.deckhouse.io/base_images@sha256:b15f9150f3b51f2e11cd73db39c89eef8a075953659caf802363d4f544335fb5"
	}

	// Load the image into the kind nodes beforehand, so the pod start does not
	// depend on pulling from the external registry over a slow CI network.
	pythonImage = kindCluster.LoadDockerImage(t, pythonImage, "lib-connection-test/python-exec:test")

	generalParams := createPodForExecTest(t, execTest, pythonImage, kubeProvider)

	clonePodParams := func() *connection.PodExecParams {
		return &connection.PodExecParams{
			Namespace: generalParams.Namespace,
			Name:      generalParams.Name,
			Container: generalParams.Container,
		}
	}

	t.Run("capture stdout", func(t *testing.T) {
		var stdout bytes.Buffer
		execParams := clonePodParams()
		execParams.Stdout = &stdout

		expectedOut := "stdout only"

		script := fmt.Sprintf(`print("%s", end="")`, expectedOut)

		err := execInPod(t, kubeProvider, execParams, script)
		require.NoError(t, err, "should exec to pod")

		require.Equal(t, expectedOut, stdout.String(), "stdout should captured")
	})

	t.Run("capture stdout with pass stderr but no out", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		execParams := clonePodParams()
		execParams.Stdout = &stdout
		execParams.Stderr = &stderr

		expectedOut := "stdout only with stderr handle"

		script := fmt.Sprintf(`print("%s", end="")`, expectedOut)

		err := execInPod(t, kubeProvider, execParams, script)
		require.NoError(t, err, "should exec to pod")

		require.Equal(t, expectedOut, stdout.String(), "stdout should captured")
		require.Empty(t, stderr.String(), "stderr should empty")
	})

	t.Run("capture stderr", func(t *testing.T) {
		var stderr bytes.Buffer
		execParams := clonePodParams()
		execParams.Stderr = &stderr

		expectedOut := "stderr only"

		script := fmt.Sprintf(`import sys; print("%s", end="", file=sys.stderr)`, expectedOut)

		err := execInPod(t, kubeProvider, execParams, script)
		require.NoError(t, err, "should exec to pod")

		require.Equal(t, expectedOut, stderr.String(), "stderr should captured")
	})

	t.Run("capture stderr and stdout", func(t *testing.T) {
		var stderr bytes.Buffer
		var stdout bytes.Buffer
		execParams := clonePodParams()
		execParams.Stderr = &stderr
		execParams.Stdout = &stdout

		expectedStderr := "stderr mul"
		expectedStdout := "stdout mul"

		scriptTpl := `
import sys 
print("%s", end="")
print("%s", end="", file=sys.stderr)
`

		script := fmt.Sprintf(scriptTpl, expectedStdout, expectedStderr)

		err := execInPod(t, kubeProvider, execParams, script)
		require.NoError(t, err, "should exec to pod")

		require.Equal(t, expectedStderr, stderr.String(), "stderr should captured")
		require.Equal(t, expectedStdout, stdout.String(), "stdout should captured")
	})

	t.Run("pass stdin", func(t *testing.T) {
		var stdout bytes.Buffer
		execParams := clonePodParams()
		execParams.Stdout = &stdout

		stdinInput := "stdin passed"
		stdinReader := strings.NewReader(stdinInput)
		execParams.Stdin = stdinReader

		script := `
import sys
data = sys.stdin.read()
print(data, end="")
`

		err := execInPod(t, kubeProvider, execParams, script)
		require.NoError(t, err, "should exec to pod")

		require.Equal(t, stdinInput, stdout.String(), "stdout should captured")
	})
}

func getKubeProviderForExec(t *testing.T, test *tests.Test, cluster *kind.KINDCluster) *provider.DefaultKubeProvider {
	sett := test.Settings()

	restCfg, err := cluster.RESTConfig()
	require.NoError(t, err, "rest config should created")

	kubeCfg := &kube.Config{
		RestConfig: restCfg,
	}

	initializer := provider.NewErrorSSHProviderInitializer(fmt.Errorf("ssh should not used"))

	ri, err := provider.GetRunnerInterface(t.Context(), kubeCfg, sett, initializer)
	require.NoError(t, err, "runner interface should provided")

	loopParams := retry.NewEmptyParams(
		retry.WithAttempts(10),
		retry.WithWait(2*time.Second),
	)

	return provider.NewDefaultKubeProvider(sett, kubeCfg, ri).WithLoopsParams(provider.KubeProviderLoopsParams{
		InitClient:   loopParams.Clone(),
		WaitingReady: loopParams.Clone(),
	})
}

func createPodForExecTest(t *testing.T, test *tests.Test, pythonImage string, kubeProvider *provider.DefaultKubeProvider) connection.PodExecParams {
	ctx := t.Context()
	cl, err := kubeProvider.Client(ctx)
	require.NoError(t, err, "client should get")

	ns := "default"
	name := tests.RandString(10)
	name = fmt.Sprintf("test-exec-%s", strings.ToLower(name))
	container := "python"

	falsePtr := false

	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
		},
		Spec: corev1.PodSpec{
			AutomountServiceAccountToken: &falsePtr,
			Containers: []corev1.Container{
				{
					Image:   pythonImage,
					Name:    container,
					Command: []string{"python3", "-c", "import time; time.sleep(3600)"},
				},
			},
			Tolerations: []corev1.Toleration{
				{
					Operator: corev1.TolerationOpExists,
				},
			},
		},
	}

	createLoop := retry.NewEmptyParams(
		retry.WithName("Create pod %s for test", name),
		retry.WithAttempts(30),
		retry.WithWait(time.Second),
		retry.WithLogger(test.GetLogger()),
	)

	err = retry.NewLoopWithParams(createLoop).RunContext(ctx, func() error {
		_, err := cl.CoreV1().Pods(ns).Create(ctx, &pod, metav1.CreateOptions{})
		return err
	})
	require.NoError(t, err, "pod should created")

	waitLoop := retry.NewEmptyParams(
		retry.WithName("Wait pod %s running for test", name),
		retry.WithAttempts(300),
		retry.WithWait(time.Second),
		retry.WithLogger(test.GetLogger()),
	)

	err = retry.NewLoopWithParams(waitLoop).RunContext(ctx, func() error {
		pd, err := cl.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}

		phase := pd.Status.Phase

		if phase == corev1.PodRunning {
			return nil
		}

		return fmt.Errorf("Pod is not running %s. Conditions: %+v", phase, &pd.Status.Conditions)
	})
	require.NoError(t, err, "pod should running")

	return connection.PodExecParams{
		Namespace: ns,
		Name:      name,
		Container: container,
	}
}

func execInPod(t *testing.T, kubeProvider *provider.DefaultKubeProvider, params *connection.PodExecParams, script string) error {
	ctx := t.Context()
	cl, err := kubeProvider.Client(ctx)
	require.NoError(t, err, "should get client to exec")

	params.Command = []string{
		"python3",
		"-c",
		script,
	}

	return cl.Exec(ctx, params)
}
