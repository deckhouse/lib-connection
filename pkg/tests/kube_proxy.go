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
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/retry"
	"github.com/stretchr/testify/require"
)

func AssertKubeProxy(t *testing.T, test *Test, localServerPort string, wantError bool) {
	url := fmt.Sprintf("http://127.0.0.1:%s/api/v1/nodes", localServerPort)

	test.GetLogger().InfoContext(context.Background(), fmt.Sprintf("Assert kube proxy on '%s' want err: %v", url, wantError))

	prefixLogger := NewPrefixLogger(test.Logger).WithPrefix(test.FullName())

	defaultParams := retry.NewEmptyParams(
		retry.WithAttempts(10),
		retry.WithWait(500*time.Millisecond),
	)

	if wantError {
		dialTo := fmt.Sprintf("127.0.0.1:%s", localServerPort)

		dialParams := defaultParams.Clone(retry.WithName("Try to dial to %s", dialTo))
		getLoopParams := defaultParams.Clone(
			retry.WithName("Do request to %s after dial", url),
			retry.WithAttempts(3),
		)

		err := retry.NewLoopWithParams(dialParams).Run(func() error {
			d, err := net.DialTimeout("tcp", dialTo, 5*time.Second)
			if err == nil {
				d.Close()
			}

			_, errGet := DoGetRequest(url, getLoopParams, prefixLogger)
			if errGet == nil && err != nil {
				test.GetLogger().InfoContext(context.Background(), fmt.Sprintf("Dial not success %v but get is success", err))
			}

			return err
		})

		require.Error(t, err, "should not reach this destination %s", dialTo)
		return
	}

	requestLoop := defaultParams.Clone(retry.WithName("Check kube proxy available by %s", url))

	_, err := DoGetRequest(
		url,
		requestLoop,
		NewPrefixLogger(test.Logger).WithPrefix(test.FullName()),
	)

	require.NoError(t, err, "check local tunnel. Want error %v", wantError)
}
