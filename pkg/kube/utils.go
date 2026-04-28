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

	"github.com/name212/govalue"
	"k8s.io/client-go/kubernetes/fake"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/ssh"
	"github.com/deckhouse/lib-connection/pkg/ssh/gossh"
)

func isShouldNotInit(kubeClient connection.KubeClient) bool {
	if govalue.Nil(kubeClient) {
		return false
	}

	_, ok := kubeClient.(*ErrorKubernetesClient)
	if ok {
		return true
	}

	impl, ok := kubeClient.(*KubernetesClient)
	if !ok {
		return false
	}

	client, ok := impl.KubeClient.(*kubeClientWithExec)
	if !ok {
		return false
	}

	if govalue.Nil(client.Interface) {
		return false
	}

	_, fk := client.Interface.(*fake.Clientset)
	return fk
}

func stopProxyAndSSH(kubeClient *KubernetesClient, full bool) {
	if !govalue.Nil(kubeClient.KubeProxy) {
		kubeClient.KubeProxy.Stop(-1)
		kubeClient.KubeProxy = nil
	}

	if !full {
		return
	}

	wrapper, ok := kubeClient.NodeInterface.(*ssh.NodeInterfaceWrapper)
	if !ok {
		return
	}

	sshClient := wrapper.Client()
	if _, ok := sshClient.(*gossh.Client); ok {
		sshClient.Stop()
	}
}

func podExecParamsString(params *connection.PodExecParams) string {
	const unknown = "<not pass>"
	name := unknown
	namespace := unknown
	container := unknown
	cmd := unknown

	if !govalue.Nil(params) {
		name = params.Name
		namespace = params.Namespace
		container = params.Container
		cmd = strings.Join(params.Command, " ")
	}

	return fmt.Sprintf(
		"container '%s' pod %s/%s cmd '%s'",
		container,
		namespace,
		name,
		cmd,
	)
}
