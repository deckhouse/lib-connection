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

package pkg

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

type KubeClient interface {
	kubernetes.Interface
	Dynamic() dynamic.Interface
	APIResourceList(apiVersion string) ([]*metav1.APIResourceList, error)
	APIResource(apiVersion, kind string) (*metav1.APIResource, error)
	GroupVersionResource(apiVersion, kind string) (schema.GroupVersionResource, error)
	InvalidateDiscoveryCache()
}

type KubeProvider interface {
	// Client
	// create new client and initialize it
	// if it uses over ssh will use current ssh client
	// Created client will cache
	// if it uses client over ssh can create new client
	// if ssh client was switched
	Client(ctx context.Context) (KubeClient, error)

	// NewAdditionalClient
	// create new additional client and initialize it
	// if use over ssh create new ssh client for it
	// you should call kube.Stop if client does not need. kube.Stop
	// save for all clients not only over ssh
	// also provider save all these clients for stop in Cleanup
	NewAdditionalClient(ctx context.Context) (KubeClient, error)

	// NewAdditionalClientWithoutInitialize
	// create new additional client without initialize
	// if use over ssh create new ssh client for it
	// you should call kube.Stop if client does not need. kube.Stop
	// save for all clients not only over ssh
	// also provider save all these clients for stop in Cleanup
	NewAdditionalClientWithoutInitialize(ctx context.Context) (KubeClient, error)

	// Cleanup
	// Stops all additional clients got from NewAdditionalClient and NewAdditionalClientWithoutInitialize
	Cleanup(ctx context.Context) error
}
