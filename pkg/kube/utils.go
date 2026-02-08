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
	klient "github.com/flant/kube-client/client"
	"github.com/name212/govalue"
	"k8s.io/client-go/kubernetes/fake"

	connection "github.com/deckhouse/lib-connection/pkg"
)

func isFake(kubeClient connection.KubeClient) bool {
	if govalue.Nil(kubeClient) {
		return false
	}

	client, ok := kubeClient.(*klient.Client)
	if !ok {
		return false
	}

	if govalue.Nil(client.Interface) {
		return false
	}

	_, fk := client.Interface.(*fake.Clientset)
	return fk
}
