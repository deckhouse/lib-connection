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
	"net/http"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	connection "github.com/deckhouse/lib-connection/pkg"
)

var (
	_ connection.KubeClient = &ErrorKubernetesClient{}
)

type ErrorKubernetesClient struct {
	kubernetes.Interface
	PodCommandExecutor

	dynamic dynamic.Interface
	err     error
}

func NewErrorKubernetesClient(errToReturn error) (*ErrorKubernetesClient, error) {
	config := &rest.Config{
		Host:      "127.0.0.1:0",
		Transport: &errorRoundTripper{err: errToReturn},
	}

	k, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	d, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &ErrorKubernetesClient{
		Interface:          k,
		dynamic:            d,
		err:                errToReturn,
		PodCommandExecutor: NewErrorPodCommandExecutor(err),
	}, nil
}

func (i *ErrorKubernetesClient) Dynamic() dynamic.Interface {
	return i.dynamic
}

func (i *ErrorKubernetesClient) APIResourceList(apiVersion string) ([]*metav1.APIResourceList, error) {
	return nil, fmt.Errorf("cannot get APIResourceList for %s: %w", apiVersion, i.err)
}

func (i *ErrorKubernetesClient) APIResource(apiVersion, kind string) (*metav1.APIResource, error) {
	return nil, fmt.Errorf("cannot get APIResource for %s/%s: %w", apiVersion, kind, i.err)
}

func (i *ErrorKubernetesClient) GroupVersionResource(apiVersion, kind string) (schema.GroupVersionResource, error) {
	return schema.GroupVersionResource{}, fmt.Errorf("cannot get GroupVersionResource for %s/%s: %w", apiVersion, kind, i.err)
}

func (i *ErrorKubernetesClient) InvalidateDiscoveryCache() {}

type errorRoundTripper struct {
	err error
}

// RoundTrip implements the http.RoundTripper interface.
func (r *errorRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, r.err
	}

	return nil, fmt.Errorf("cannot send request %s %s: %w", req.Method, req.RequestURI, r.err)
}
