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
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// AcquireGlobalTestLock takes an exclusive inter-process lock with the given
// name and holds it until the test finishes. Use it for tests that occupy
// globally shared resources (e.g. the fixed kube-proxy local API port), which
// would collide when test binaries of different packages run in parallel.
func AcquireGlobalTestLock(t *testing.T, name string) {
	t.Helper()

	path := filepath.Join(os.TempDir(), fmt.Sprintf("lib-connection-test-%s.lock", name))

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o666)
	require.NoError(t, err, "should open lock file %s", path)

	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
	require.NoError(t, err, "should lock %s", path)

	t.Cleanup(func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	})
}
