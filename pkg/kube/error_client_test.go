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
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	applyconf "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
)

func TestErrorKubernetesClient(t *testing.T) {
	failError := fmt.Errorf("use error kube client")
	getErrorClient := func(t *testing.T) *ErrorKubernetesClient {
		c, err := NewErrorKubernetesClient(failError)
		require.NoError(t, err, "error client should be created")
		return c
	}

	assertError := func(t *testing.T, do func() error) {
		doNotPanics := func() {
			err := do()

			require.Error(t, err, "should return error")
			require.ErrorIs(t, err, failError)
		}

		require.NotPanics(t, doNotPanics, "should not panic")
	}

	t.Run("default interface", func(t *testing.T) {
		client := getErrorClient(t)

		ctx := context.TODO()
		cmClient := client.CoreV1().ConfigMaps("default")

		assertError(t, func() error {
			_, err := cmClient.Get(ctx, "foo", metav1.GetOptions{})
			return err
		})

		assertError(t, func() error {
			_, err := cmClient.List(ctx, metav1.ListOptions{})
			return err
		})

		cm := v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default",
				Name:      "foo",
			},
			Data: map[string]string{
				"key": "value",
			},
		}

		assertError(t, func() error {
			_, err := cmClient.Create(ctx, &cm, metav1.CreateOptions{})
			return err
		})

		assertError(t, func() error {
			_, err := cmClient.Update(ctx, &cm, metav1.UpdateOptions{})
			return err
		})

		assertError(t, func() error {
			applyCm := applyconf.ConfigMapApplyConfiguration{}
			applyCm.WithName("foo").WithData(map[string]string{"key": "value"})
			_, err := cmClient.Apply(ctx, &applyCm, metav1.ApplyOptions{})
			return err
		})

		assertError(t, func() error {
			return cmClient.Delete(ctx, "foo", metav1.DeleteOptions{})
		})

		assertError(t, func() error {
			return cmClient.DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{})
		})

		assertError(t, func() error {
			data := []byte(`{"var": "foo"}`)
			_, err := cmClient.Patch(ctx, "foo", types.JSONPatchType, data, metav1.PatchOptions{})
			return err
		})

		assertError(t, func() error {
			_, err := cmClient.Watch(ctx, metav1.ListOptions{})
			return err
		})

		// without namespace
		assertError(t, func() error {
			_, err := client.CoreV1().Nodes().Get(ctx, "foo", metav1.GetOptions{})
			return err
		})
	})

	t.Run("dynamic", func(t *testing.T) {
		client := getErrorClient(t)

		ctx := context.TODO()

		gvr := schema.GroupVersionResource{
			Group:    "deckhouse.io",
			Version:  "v1",
			Resource: "nodeusers",
		}

		dClient := client.Dynamic().Resource(gvr).Namespace("default")

		assertError(t, func() error {
			_, err := dClient.Get(ctx, "foo", metav1.GetOptions{})
			return err
		})

		assertError(t, func() error {
			_, err := dClient.List(ctx, metav1.ListOptions{})
			return err
		})

		obj := &unstructured.Unstructured{}
		docData := []byte(`
apiVersion: deckhouse.io/v1
kind: NodeUser
metadata:
  name: tes
spec:
  isSudoer: false
  nodeGroups:
  - '*'
  passwordHash: "6"
  sshPublicKey: ssh-rsa AAA
  uid: 1001
`)
		_, _, err := scheme.Codecs.UniversalDecoder().Decode(docData, nil, obj)
		require.NoError(t, err, "should marshal to unstructured")

		assertError(t, func() error {
			_, err := dClient.Create(ctx, obj, metav1.CreateOptions{})
			return err
		})

		assertError(t, func() error {
			_, err := dClient.Update(ctx, obj, metav1.UpdateOptions{})
			return err
		})

		assertError(t, func() error {
			_, err := dClient.Apply(ctx, "foo", obj, metav1.ApplyOptions{})
			return err
		})

		assertError(t, func() error {
			return dClient.Delete(ctx, "foo", metav1.DeleteOptions{})
		})

		assertError(t, func() error {
			return dClient.DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{})
		})

		assertError(t, func() error {
			data := []byte(`{"var": "foo"}`)
			_, err := dClient.Patch(ctx, "foo", types.JSONPatchType, data, metav1.PatchOptions{})
			return err
		})

		assertError(t, func() error {
			_, err := dClient.Watch(ctx, metav1.ListOptions{})
			return err
		})

		// without namespace
		assertError(t, func() error {
			_, err := client.Dynamic().Resource(gvr).Get(ctx, "foo", metav1.GetOptions{})
			return err
		})
	})

	t.Run("our interface", func(t *testing.T) {
		client := getErrorClient(t)

		assertError(t, func() error {
			_, err := client.APIResourceList("v1")
			return err
		})

		assertError(t, func() error {
			_, err := client.APIResource("v1", "Node")
			return err
		})

		assertError(t, func() error {
			_, err := client.GroupVersionResource("v1", "Node")
			return err
		})

		doInvalidate := func() {
			client.InvalidateDiscoveryCache()
		}

		require.NotPanics(t, doInvalidate, "InvalidateDiscoveryCache should not panic")
	})
}
