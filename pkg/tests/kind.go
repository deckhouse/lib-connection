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
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/retry"
)

const (
	KindConfigPath  = "../../../hack/kind/cluster-kube-proxy.yml"
	KindClusterName = "k8s-test"
	KindBinary      = "../../../bin/kind"
)

func CreateKINDCluster() error {
	// checking out, what kind config exists
	_, err := os.Stat(KindConfigPath)
	if err != nil {
		return err
	}
	// args to command
	args := []string{"create", "cluster", "--name=" + KindClusterName, "--config=" + KindConfigPath}
	cmd := exec.Command(KindBinary, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("could not create kind cluster: %s: %w\n", out, err)
	}

	return err
}

func DeleteKindCluster() error {
	args := []string{"delete", "cluster", "--name=" + KindClusterName}
	cmd := exec.Command(KindBinary, args...)

	return cmd.Run()
}

func GetKINDControlPlaneIP() (string, error) {
	getIPCmd := []string{
		"inspect",
		"-f", "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
		KindClusterName + "-control-plane",
	}
	ip := ""

	err := retry.NewSilentLoop("discovering IP of control plane noe", 10, 2*time.Second).Run(func() error {
		cmd := exec.Command("docker", getIPCmd...)
		out, err := cmd.Output()
		if err != nil {
			return err
		}
		ip = string(out)
		return nil
	})
	if err != nil {
		return "", err
	}

	return ip, nil
}

func GetKINDKubeconfig() (string, error) {
	args := []string{"get", "kubeconfig", "--name=" + KindClusterName}
	cmd := exec.Command(KindBinary, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("couldn't get kind kubeconfig: %s: %w", string(out), err)
	}

	return string(out), nil
}
