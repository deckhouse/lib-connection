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

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/retry"
	"github.com/stretchr/testify/require"

	connection "github.com/deckhouse/lib-connection/pkg"
)

const (
	KindBinary = "../../../bin/kind"
	kindConfig = `
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
`
)

var (
	extractPortRe = regexp.MustCompile(`server:\s+https:\/\/127\.0\.0\.1:([0-9]{2,5})`)
)

type KINDClusterCreateParams struct {
	Test        *Test
	ClusterName string
	SSHClient   connection.SSHClient
	Container   *TestContainerWrapper
}

type KINDCluster struct {
	Name             string
	ControlPlaneIP   string
	ControlPlanePort string

	test       *Test
	kubeconfig string
}

func (c *KINDCluster) appendClusterNameArg(args []string) []string {
	return append(args, fmt.Sprintf("--name=%s", c.Name))
}

func (c *KINDCluster) runKind(args ...string) (string, error) {
	cmd := exec.Command(KindBinary, c.appendClusterNameArg(args)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (c *KINDCluster) RegisterCleanup(t *testing.T) {
	t.Cleanup(func() {
		if err := c.Delete(); err != nil {
			c.test.GetLogger().ErrorF("Failed to delete cluster %s: %s", c.Name, err)
		}
	})
}

func (c *KINDCluster) Delete() error {
	logger := c.test.GetLogger()
	logger.InfoF("Deleting KIND cluster %s...", c.Name)
	out, err := c.runKind("delete", "cluster")
	if err != nil {
		logger.ErrorF("Failed to delete KIND cluster %s: %v:\n%s", c.Name, err, out)
		return err
	}

	logger.InfoF("KIND Cluster %s deleted:\n%s", c.Name, out)
	return nil
}

// extractPort
// first port, second whole server string
func (c *KINDCluster) extractPort() (string, string) {
	submatches := extractPortRe.FindStringSubmatch(c.kubeconfig)
	if len(submatches) != 2 {
		return "", ""
	}

	return submatches[1], submatches[0]
}

func (c *KINDCluster) containerName() string {
	return fmt.Sprintf("%s-control-plane", c.Name)
}

func (c *KINDCluster) Kubeconfig() string {
	return c.kubeconfig
}

// KubeconfigWithIP
// ip and port can empty if empty returns raw
func (c *KINDCluster) KubeconfigWithIP(ip string, port string) string {
	if ip == "" {
		return c.kubeconfig
	}

	extractedPort, full := c.extractPort()

	if port == "" {
		port = extractedPort
	}

	replace := fmt.Sprintf("server: https://%s:%s", ip, port)

	return strings.ReplaceAll(c.kubeconfig, full, replace)
}

func CreateKINDCluster(t *testing.T, params *KINDClusterCreateParams) *KINDCluster {
	test := params.Test

	configPath := test.MustCreateTmpFile(t, kindConfig, false, "kind-config.yaml")
	clusterName := fmt.Sprintf("test-connection-%s", params.ClusterName)

	cluster := &KINDCluster{
		test: test,
		Name: clusterName,
	}

	// args to command
	args := []string{
		"create",
		"cluster",
		fmt.Sprintf("--config=%s", configPath),
	}

	test.GetLogger().InfoF("Creating KIND cluster %s...", clusterName)

	out, err := cluster.runKind(args...)
	require.NoError(t, err, "not create kind cluster: %w:%s\n", out)

	test.GetLogger().InfoF("KIND cluster %s created:\n%s", clusterName, out)

	container := params.Container.Container

	err = container.DockerNetworkConnect(false, "kind")
	checkErrorDuringCreateCluster(t, cluster, err, "failed to connect ssh container to kind cluster")

	cluster.ControlPlaneIP, err = getKINDControlPlaneIP(cluster)
	checkErrorDuringCreateCluster(t, cluster, err, "failed to get kind control plane IP")

	cluster.kubeconfig, err = getKINDKubeconfig(cluster)
	checkErrorDuringCreateCluster(t, cluster, err, "failed to get kind control plane IP")

	cluster.ControlPlanePort, _ = cluster.extractPort()

	newKubeconfig := cluster.KubeconfigWithIP(cluster.ControlPlaneIP, "6443")

	err = container.CreateDirectory("/config/.kube")
	checkErrorDuringCreateCluster(t, cluster, err, "failed to create kind config directory on ssh")

	configTmp, err := test.CreateTmpFile(newKubeconfig, false, "kubeconfig")
	checkErrorDuringCreateCluster(t, cluster, err, "failed to create kind config file to upload")

	file := params.SSHClient.File()
	uploadParams := retry.NewEmptyParams(
		retry.WithName("Upload kubeconfig to ssh container"),
		retry.WithAttempts(10),
		retry.WithWait(2*time.Second),
		retry.WithLogger(test.GetLogger()),
	)
	err = retry.NewLoopWithParams(uploadParams).Run(func() error {
		return file.Upload(context.Background(), configTmp, "/config/.kube/config")
	})
	checkErrorDuringCreateCluster(t, cluster, err, "failed to upload kubeconfig to ssh container")

	err = container.CreateDirectory("/etc/kubernetes/")
	checkErrorDuringCreateCluster(t, cluster, err, "failed to create directory /etc/kubernetes")

	err = container.ExecToContainer(
		"symlink of kubeconfig",
		"ln",
		"-s",
		"/config/.kube/config",
		"/etc/kubernetes/admin.conf",
	)
	checkErrorDuringCreateCluster(t, cluster, err, "failed to create link to kube config")

	kubectlVersion, err := getKubectlVersion(cluster)
	checkErrorDuringCreateCluster(t, cluster, err, "failed to get kubectl version")

	downloadKubectlParams := retry.NewEmptyParams(
		retry.WithName("Download kubectl to ssh container"),
		retry.WithAttempts(10),
		retry.WithWait(2*time.Second),
		retry.WithLogger(test.GetLogger()),
	)
	err = retry.NewLoopWithParams(downloadKubectlParams).Run(func() error {
		return container.DownloadKubectl(kubectlVersion)
	})
	checkErrorDuringCreateCluster(t, cluster, err, "failed to download kubectl to ssh container")

	return cluster
}

func runDockerForKINDContainer(cluster *KINDCluster, name string, args ...string) (string, error) {
	params := retry.NewEmptyParams(
		retry.WithName("%s", name),
		retry.WithAttempts(10),
		retry.WithWait(2*time.Second),
		retry.WithLogger(cluster.test.GetLogger()),
	)

	out := ""

	err := retry.NewLoopWithParams(params).Run(func() error {
		var err error
		out, err = RunDockerWithOut(args...)
		out = strings.TrimSpace(out)
		return err
	})

	if err != nil {
		return "", err
	}

	return out, nil
}

func getKubectlVersion(cluster *KINDCluster) (string, error) {
	args := []string{
		"exec",
		cluster.containerName(),
		"kubectl",
		"version",
		"--client",
		"-o",
		"json",
	}

	out, err := runDockerForKINDContainer(cluster, "Get kubectl version", args...)
	if err != nil {
		return "", err
	}

	type clientVersion struct {
		GitVersion string `json:"gitVersion"`
	}

	type version struct {
		ClientVersion clientVersion `json:"clientVersion"`
	}

	v := version{}
	err = json.Unmarshal([]byte(out), &v)
	if err != nil {
		return "", err
	}

	if v.ClientVersion.GitVersion == "" {
		return "", fmt.Errorf("failed to get kubectl version")
	}

	return v.ClientVersion.GitVersion, nil
}

func getKINDControlPlaneIP(cluster *KINDCluster) (string, error) {
	args := []string{
		"inspect",
		"-f", "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
		cluster.containerName(),
	}

	return runDockerForKINDContainer(cluster, "Discovering IP of control plane node", args...)
}

func getKINDKubeconfig(cluster *KINDCluster) (string, error) {
	out, err := cluster.runKind("get", "kubeconfig")
	if err != nil {
		return "", fmt.Errorf("couldn't get kind kubeconfig: %s: %w", out, err)
	}

	return out, nil
}

func checkErrorDuringCreateCluster(t *testing.T, cluster *KINDCluster, err error, msg string) {
	t.Helper()

	if err == nil {
		return
	}

	deleteErr := cluster.Delete()
	if deleteErr != nil {
		cluster.test.GetLogger().ErrorF("Cannot delete kind cluster %s after create fail: %w", cluster.Name, deleteErr)
	}

	require.NoError(t, err, msg)
}
