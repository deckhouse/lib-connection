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

	klient "github.com/flant/kube-client/client"
	"github.com/name212/govalue"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"

	connection "github.com/deckhouse/lib-connection/pkg"
)

type PodCommandExecutor interface {
	Exec(ctx context.Context, params *connection.PodExecParams) error
}

type regularPodExecutor struct {
	client *klient.Client
}

func newRegularPodExecutor(cl *klient.Client) *regularPodExecutor {
	return &regularPodExecutor{
		client: cl,
	}
}

func (e *regularPodExecutor) Exec(ctx context.Context, params *connection.PodExecParams) error {
	podOpts, streamOpts, err := prepareAndCreateExecParams(params)
	if err != nil {
		return err
	}

	namespace := params.Namespace

	if namespace == "" {
		namespace = "default"
	}

	req := e.client.CoreV1().RESTClient().Post().
		Resource("pods").
		Namespace(namespace).
		Name(params.Name).
		SubResource("exec")

	req.VersionedParams(podOpts, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(e.client.RestConfig(), "POST", req.URL())
	if err != nil {
		return fmt.Errorf(
			"failed to create executor for exec %s: %w",
			podExecParamsString(params),
			err,
		)
	}

	err = executor.StreamWithContext(ctx, *streamOpts)
	if err != nil {
		return fmt.Errorf(
			"failed to exec stream %s: %w",
			podExecParamsString(params),
			err,
		)
	}

	return nil
}

type errorPodCommandExecutor struct {
	err error
}

func newErrorPodCommandExecutor(err error) *errorPodCommandExecutor {
	if err == nil {
		err = fmt.Errorf("errorPodCommandExecutor: error did not pass")
	}

	return &errorPodCommandExecutor{
		err: err,
	}
}

func (e *errorPodCommandExecutor) Exec(ctx context.Context, params *connection.PodExecParams) error {
	return fmt.Errorf("Cannot exec in %s: %w", podExecParamsString(params), e.err)
}

func prepareAndCreateExecParams(p *connection.PodExecParams) (*corev1.PodExecOptions, *remotecommand.StreamOptions, error) {
	if govalue.Nil(p) {
		return nil, nil, fmt.Errorf("PodExecParams did not pass")
	}

	if p.Name == "" {
		return nil, nil, fmt.Errorf("PodExecParams: pod name is not set")
	}

	if p.Container == "" {
		return nil, nil, fmt.Errorf("PodExecParams: target container is not set")
	}

	if len(p.Command) == 0 {
		return nil, nil, fmt.Errorf("PodExecParams: command is not set")
	}

	podOpts := &corev1.PodExecOptions{
		Command:   p.Command,
		Container: p.Container,
		Stdin:     false,
		Stdout:    false,
		Stderr:    false,
		TTY:       false,
	}

	streamOpts := remotecommand.StreamOptions{
		Stdin:  nil,
		Stdout: nil,
		Stderr: nil,
		Tty:    false,
	}

	if !govalue.Nil(p.Stdin) {
		podOpts.Stdin = true
		streamOpts.Stdin = p.Stdin
	}

	if !govalue.Nil(p.Stdout) {
		podOpts.Stdout = true
		streamOpts.Stdout = p.Stdout
	}

	if !govalue.Nil(p.Stderr) {
		podOpts.Stderr = true
		streamOpts.Stderr = p.Stderr
	}

	return podOpts, &streamOpts, nil
}
