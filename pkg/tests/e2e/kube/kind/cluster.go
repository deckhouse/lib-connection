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
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/retry"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/tests"
)

const (
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

type SSHContainersForKind struct {
	Client    connection.SSHClient
	Container *tests.TestContainerWrapper
}

type KINDClusterCreateParams struct {
	Test        *tests.Test
	ClusterName string
	Containers  []*SSHContainersForKind

	NoPrepareLocalKubectlInSSHContainer bool
}

type KINDCluster struct {
	Name             string
	ControlPlaneIP   string
	ControlPlanePort string

	test       *tests.Test
	kubeconfig string
	restConfig *rest.Config
}

func (c *KINDCluster) appendClusterNameArg(args []string) []string {
	return append(args, fmt.Sprintf("--name=%s", c.Name))
}

func (c *KINDCluster) runKind(args ...string) (string, error) {
	cmd := exec.Command(getKINDBinary(), c.appendClusterNameArg(args)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (c *KINDCluster) RegisterCleanup(t *testing.T) {
	t.Cleanup(func() {
		if err := c.Delete(); err != nil {
			c.test.GetLogger().ErrorContext(context.Background(), fmt.Sprintf("Failed to delete cluster %s: %s", c.Name, err))
		}
	})
}

func (c *KINDCluster) Delete() error {
	logger := c.test.GetLogger()
	logger.InfoContext(context.Background(), fmt.Sprintf("Deleting KIND cluster %s...", c.Name))
	out, err := c.runKind("delete", "cluster")
	if err != nil {
		logger.ErrorContext(context.Background(), fmt.Sprintf("Failed to delete KIND cluster %s: %v:\n%s", c.Name, err, out))
		return err
	}

	logger.InfoContext(context.Background(), fmt.Sprintf("KIND Cluster %s deleted:\n%s", c.Name, out))
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

func (c *KINDCluster) RESTConfig() (*rest.Config, error) {
	if c.restConfig != nil {
		return c.copyREST(), nil
	}

	config, err := clientcmd.Load([]byte(c.Kubeconfig()))
	if err != nil {
		return nil, err
	}

	cluster, ok := config.Clusters[fmt.Sprintf("kind-%s", c.Name)]
	if !ok {
		return nil, fmt.Errorf("cluster %s not found in kubeconfig", c.Name)
	}

	ca := cluster.CertificateAuthorityData
	if len(ca) == 0 {
		return nil, fmt.Errorf("no CA data for cluster %s", c.Name)
	}

	saName := "test-kube-admin"

	_, err = c.runKubectlInSystemNs("Create SA for token", "create", "serviceaccount", saName)
	if err != nil {
		return nil, err
	}

	roleBindingArgs := []string{
		"create",
		"clusterrolebinding",
		"test-kube-admin-binding",
		"--clusterrole=cluster-admin",
		fmt.Sprintf("--serviceaccount=kube-system:%s", saName),
	}

	_, err = c.runKubectlInSystemNs("Create role binding", roleBindingArgs...)
	if err != nil {
		return nil, err
	}

	token, err := c.runKubectlInSystemNs("Create token", "create", "token", saName)
	if err != nil {
		return nil, err
	}

	c.restConfig = &rest.Config{
		Host:        fmt.Sprintf("https://127.0.0.1:%s", c.ControlPlanePort),
		BearerToken: token,
		TLSClientConfig: rest.TLSClientConfig{
			CAData: ca,
		},
	}

	return c.copyREST(), nil
}

func (c *KINDCluster) copyREST() *rest.Config {
	ca := c.restConfig.TLSClientConfig.CAData

	cpy := *c.restConfig
	cpyCA := make([]byte, len(ca))
	copy(cpyCA, ca)

	cpy.TLSClientConfig.CAData = cpyCA

	return &cpy
}

func (c *KINDCluster) runKubectlInSystemNs(name string, args ...string) (string, error) {
	// nolint:prealloc
	runArgs := []string{
		"kubectl",
		"-n",
		"kube-system",
	}

	runArgs = append(runArgs, args...)

	return execInKINDContainer(c, name, runArgs...)
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

	test.GetLogger().InfoContext(context.Background(), fmt.Sprintf("Creating KIND cluster %s...", clusterName))

	out, err := cluster.runKind(args...)
	require.NoError(t, err, "not create kind cluster: %w:%s\n", err, out)

	test.GetLogger().InfoContext(context.Background(), fmt.Sprintf("KIND cluster %s created:\n%s", clusterName, out))

	cluster.ControlPlaneIP, err = getKINDControlPlaneIP(cluster)
	checkErrorDuringCreateCluster(t, cluster, err, "failed to get kind control plane IP")

	cluster.kubeconfig, err = getKINDKubeconfig(cluster)
	checkErrorDuringCreateCluster(t, cluster, err, "failed to get kind control plane IP")

	cluster.ControlPlanePort, _ = cluster.extractPort()

	kubectlPreparator := newLocalKubectlPreparator(cluster)

	for _, sshContainer := range params.Containers {
		container := sshContainer.Container.Container
		containerName := container.ContainerSettings().ContainerName

		err = container.DockerNetworkConnect(false, "kind")
		checkErrorDuringCreateCluster(t, cluster, err, "failed to connect ssh container %s to kind cluster", containerName)

		if !params.NoPrepareLocalKubectlInSSHContainer {
			kubectlPreparator.prepareLocalKubeCtlInSSHContainer(t, sshContainer)
		} else {
			params.Test.GetLogger().InfoContext(context.Background(), fmt.Sprintf("Skipping prepare local kubectl in ssh container %s", containerName))
		}
	}

	return cluster
}

// LoadDockerImage pulls sourceImage into the local docker daemon, retags it
// and loads it into the cluster nodes, so pods do not pull from an external
// registry. Returns the tag to use in pod specs: kind cannot load
// digest-only references, so the image is loaded under targetTag.
func (c *KINDCluster) LoadDockerImage(t *testing.T, sourceImage, targetTag string) string {
	t.Helper()

	_, err := runDockerForKINDContainer(c, fmt.Sprintf("Pull image %s", sourceImage), "pull", sourceImage)
	require.NoError(t, err, "failed to pull image %s", sourceImage)

	_, err = runDockerForKINDContainer(c, fmt.Sprintf("Tag image %s as %s", sourceImage, targetTag), "tag", sourceImage, targetTag)
	require.NoError(t, err, "failed to tag image %s as %s", sourceImage, targetTag)

	loadParams := retry.NewEmptyParams(
		retry.WithName("Load image %s into KIND cluster %s", targetTag, c.Name),
		retry.WithAttempts(10),
		retry.WithWait(2*time.Second),
	)

	err = retry.NewLoopWithParams(loadParams).Run(func() error {
		out, err := c.runKind("load", "docker-image", targetTag)
		if err != nil {
			return fmt.Errorf("%s: %w", out, err)
		}
		return nil
	})
	require.NoError(t, err, "failed to load image %s into kind cluster %s", targetTag, c.Name)

	return targetTag
}

func execInKINDContainer(cluster *KINDCluster, name string, args ...string) (string, error) {
	// nolint:prealloc
	a := []string{
		"exec",
		cluster.containerName(),
	}

	a = append(a, args...)

	return runDockerForKINDContainer(cluster, name, a...)
}

func runDockerForKINDContainer(_ *KINDCluster, name string, args ...string) (string, error) {
	params := retry.NewEmptyParams(
		retry.WithName("%s", name),
		retry.WithAttempts(10),
		retry.WithWait(2*time.Second),
	)

	out := ""

	err := retry.NewLoopWithParams(params).Run(func() error {
		var err error
		out, err = tests.RunDockerWithOut(args...)
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
		"kubectl",
		"version",
		"--client",
		"-o",
		"json",
	}

	out, err := execInKINDContainer(cluster, "Get kubectl version", args...)
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

func checkErrorDuringCreateCluster(t *testing.T, cluster *KINDCluster, err error, msg string, args ...any) {
	t.Helper()

	if err == nil {
		return
	}

	deleteErr := cluster.Delete()
	if deleteErr != nil {
		cluster.test.GetLogger().ErrorContext(context.Background(), fmt.Sprintf("Cannot delete kind cluster %s after create fail: %v", cluster.Name, deleteErr))
	}

	require.NoError(t, err, fmt.Sprintf(msg, args...))
}

type localKubectlPreparator struct {
	kubectlVersion string
	configPath     string
	cluster        *KINDCluster
}

func newLocalKubectlPreparator(cluster *KINDCluster) *localKubectlPreparator {
	return &localKubectlPreparator{
		cluster: cluster,
	}
}

func (p *localKubectlPreparator) getKubectlVersion(t *testing.T) string {
	if p.kubectlVersion != "" {
		return p.kubectlVersion
	}

	kubectlVersion, err := getKubectlVersion(p.cluster)
	checkErrorDuringCreateCluster(t, p.cluster, err, "failed to get kubectl version")

	p.kubectlVersion = kubectlVersion
	return kubectlVersion
}

func (p *localKubectlPreparator) getKubeConfigPath(t *testing.T) string {
	if p.configPath != "" {
		return p.configPath
	}

	cluster := p.cluster

	newKubeconfig := cluster.KubeconfigWithIP(cluster.ControlPlaneIP, "6443")

	configTmp, err := cluster.test.CreateTmpFile(newKubeconfig, false, "kubeconfig")
	checkErrorDuringCreateCluster(t, cluster, err, "failed to create kind config file to upload")

	p.configPath = configTmp
	return configTmp
}

func (p *localKubectlPreparator) prepareLocalKubeCtlInSSHContainer(t *testing.T, sshContainer *SSHContainersForKind) {
	container := sshContainer.Container.Container
	containerName := container.ContainerSettings().ContainerName
	cluster := p.cluster

	kubectlVersion := p.getKubectlVersion(t)

	downloadKubectlParams := retry.NewEmptyParams(
		retry.WithName("Download kubectl to ssh container %s", containerName),
		retry.WithAttempts(10),
		retry.WithWait(2*time.Second),
	)
	err := retry.NewLoopWithParams(downloadKubectlParams).Run(func() error {
		return container.DownloadKubectl(kubectlVersion)
	})
	checkErrorDuringCreateCluster(t, cluster, err, "failed to download kubectl to ssh container %s", containerName)

	err = container.CreateDirectory("/config/.kube")
	checkErrorDuringCreateCluster(t, cluster, err, "failed to create kube config directory in ssh container %s", containerName)

	file := sshContainer.Client.File()
	uploadParams := retry.NewEmptyParams(
		retry.WithName("Upload kubeconfig to ssh container %s", containerName),
		retry.WithAttempts(10),
		retry.WithWait(2*time.Second),
	)

	configTmp := p.getKubeConfigPath(t)

	err = retry.NewLoopWithParams(uploadParams).Run(func() error {
		return file.Upload(context.Background(), configTmp, "/config/.kube/config")
	})
	checkErrorDuringCreateCluster(t, cluster, err, "failed to upload kubeconfig to ssh container")

	err = container.CreateDirectory("/etc/kubernetes/")
	checkErrorDuringCreateCluster(t, cluster, err, "failed to create directory /etc/kubernetes on ssh container %s", containerName)

	err = container.ExecToContainer(
		"symlink of kubeconfig",
		"ln",
		"-s",
		"/config/.kube/config",
		"/etc/kubernetes/admin.conf",
	)
	checkErrorDuringCreateCluster(t, cluster, err, "failed to create link to kube config on ssh container %s", containerName)
}

func getKINDBinary() string {
	if bin := os.Getenv("TEST_KIND_BINARY"); bin != "" {
		return bin
	}

	return "../../../../bin/kind"
}
