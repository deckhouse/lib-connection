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
	"bufio"
	"bytes"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func PrepareFakeBashibleBundle(t *testing.T, test *Test, entrypoint, bundleDir string) string {
	bundleDirPath := func() []string {
		return []string{"bundle_test", bundleDir}
	}

	parentDir := test.MustMkSubDirs(t, bundleDirPath()...)

	entrypointScript := `#!/bin/bash

echo "starting execute steps..."

BUNDLE_STEPS_DIR=/var/lib/bashible/bundle_steps
BOOTSTRAP_DIR=/var/lib/bashible
MAX_RETRIES=3

for arg in "$@"; do
  if [[ "$arg" == "--add-failure" ]]
    then
      echo "failures included"
      export INCLUDE_FAILURE=true
  fi
done

# Execute bashible steps
for step in $BUNDLE_STEPS_DIR/*; do
  echo ===
  echo === Step: $step
  echo ===
  attempt=0
  sx=""
  until /bin/bash --noprofile --norc -"$sx"eEo pipefail -c "export TERM=xterm-256color; unset CDPATH; cd $BOOTSTRAP_DIR; source $step" 2> >(tee /var/lib/bashible/step.log >&2)
  do
    attempt=$(( attempt + 1 ))
    if [ -n "${MAX_RETRIES-}" ] && [ "$attempt" -gt "${MAX_RETRIES}" ]; then
      >&2 echo "ERROR: Failed to execute step $step. Retry limit is over."
      exit 1
    fi
    >&2 echo "Failed to execute step "$step" ... retry in 2 seconds."
    sleep 2
    echo ===
    echo === Step: $step
    echo ===
    if [ "$attempt" -gt 1 ]; then
      sx=x
    fi
  done
done

`

	entrypointPath := append(bundleDirPath(), entrypoint)
	test.MustCreateFile(t, entrypointScript, true, entrypointPath...)

	scrips := []struct {
		name    string
		content string
	}{
		{
			name: "01-step.sh",
			content: `#!/bin/bash
echo "just a step"

for i in {0..3}
do
  sleep 2
  echo $i  
done
`,
		},
		{
			name: "02-step.sh",
			content: `#!/bin/bash

echo "second step"

for i in {0..4}
do
  sleep 1
  echo $i
  if [[ $i -gt 2 && $INCLUDE_FAILURE == "true" ]]
    then
      echo "oops! failure!"
      exit 1
  fi
done
`,
		},
	}

	for _, c := range scrips {
		scriptPath := append(bundleDirPath(), "bundle_steps", c.name)
		test.MustCreateFile(t, c.content, true, scriptPath...)
	}

	return filepath.Dir(parentDir)
}

var logTimeRegexp = regexp.MustCompile(` \(\d+\.\d+ seconds\)`)

func AssertLogBufferNoErrorBundle(t *testing.T, buf *bytes.Buffer) {
	expected := `┌ Run step 01-step.sh
└ Run step 01-step.sh

┌ Run step 02-step.sh
└ Run step 02-step.sh`

	_ = bufio.NewWriter(buf).Flush()

	out := strings.TrimSpace(buf.String())
	out = logTimeRegexp.ReplaceAllString(out, "")

	require.Equal(t, out, strings.TrimSpace(expected), "log buffer should contain")
}

func AssertLogBufferWithErrorBundle(t *testing.T, buf *bytes.Buffer) {
	_ = bufio.NewWriter(buf).Flush()

	out := strings.TrimSpace(buf.String())
	out = logTimeRegexp.ReplaceAllString(out, "")

	expectedHead := `┌ Run step 01-step.sh
└ Run step 01-step.sh

┌ Run step 02-step.sh
│ second step
│ 0
│ 1
│ 2
│ 3
│ oops! failure!
│ Failed to execute step /var/lib/bashible/bundle_steps/02-step.sh ... retry in 2 seconds.
└ Run step 02-step.sh FAILED

┌ Run step 02-step.sh, retry attempt #1 of 10
│ second step
│ 0
│ 1
│ 2
│ 3
│ oops! failure!
│ Failed to execute step /var/lib/bashible/bundle_steps/02-step.sh ... retry in 2 seconds.
└ Run step 02-step.sh, retry attempt #1 of 10 FAILED`

	require.Contains(t, out, strings.TrimSpace(expectedHead), "should contain head")

	expectedDebug := `┌ Run step 02-step.sh, retry attempt #2 of 10
│ second step
│ + export TERM=xterm-256color
│ + TERM=xterm-256color
│ + unset CDPATH
│ + cd /var/lib/bashible
│ + source /var/lib/bashible/bundle_steps/02-step.sh
│ ++ echo 'second step'`

	require.Contains(t, out, strings.TrimSpace(expectedDebug), "should contain debug")

	expectedTail := `│ oops! failure!
│ Failed to execute step /var/lib/bashible/bundle_steps/02-step.sh ... retry in 2 seconds.
└ Run step 02-step.sh, retry attempt #2 of 10 FAILED

┌ Run step 02-step.sh, retry attempt #3 of 10
└ Run step 02-step.sh, retry attempt #3 of 10 FAILED`

	require.Contains(t, out, strings.TrimSpace(expectedTail), "should contain debug")
}
