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

BOOTSTRAP_DIR=/var/lib/bashible
MAX_RETRIES=3
REWRITE_STEP_NAME=""

while [[ $# -gt 0 ]]; do
case "$1" in
  --add-failure)
	echo "failures included"
    export INCLUDE_FAILURE=true
	shift
	;;
  --info-out)
	not_ask="$not_ask_passed_val"
	export INFO_OUT=true
	shift
	;;
  --bootstrap-dir)
	BOOTSTRAP_DIR="$2"
	REWRITE_STEP_NAME="true"
	shift
	shift
	;;
  *)
    echo "Illegal option $1"
    exit 1
    ;;
esac
done

BUNDLE_STEPS_DIR="${BOOTSTRAP_DIR}/bundle_steps"

log_tmp="$(mktemp)"

# Execute bashible steps
for step in $(ls $BUNDLE_STEPS_DIR/*.sh); do
  step_out="$step"
  if [ -n "$REWRITE_STEP_NAME" ]; then
    step_out="/var/lib/bashible/bundle_steps/$(basename $step)"
  fi
  echo "==="
  echo "=== Step: $step_out"
  echo "==="
  attempt=0
  sx=""
  until /bin/bash --noprofile --norc -"$sx"eEo pipefail -c "export TERM=xterm-256color; unset CDPATH; cd $BOOTSTRAP_DIR; source $step" 2> >(tee "$log_tmp" >&2)
  do
    attempt=$(( attempt + 1 ))
    if [ -n "${MAX_RETRIES-}" ] && [ "$attempt" -gt "${MAX_RETRIES}" ]; then
      >&2 echo "ERROR: Failed to execute step $step_out. Retry limit is over."
      exit 1
    fi
    >&2 echo "Failed to execute step "$step_out" ... retry in 2 seconds."
    sleep 1
    echo "==="
    echo "=== Step: $step_out"
    echo "==="
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

if [[ $INFO_OUT == "true"  && $INCLUDE_FAILURE != "true" ]]; then
  echo "=== Step output: Capture info"
fi

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
var asciiControlRe = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func cleanASCII(out string) string {
	return asciiControlRe.ReplaceAllString(out, "")
}

func prepareAndLogBungleOutput(t *testing.T, buf *bytes.Buffer) string {
	_ = bufio.NewWriter(buf).Flush()

	out := buf.String()

	t.Logf("\n--- Got bundle out ---\n%s\n--- End bundle out ---", out)

	out = cleanASCII(strings.TrimSpace(out))
	return logTimeRegexp.ReplaceAllString(out, "")
}

func AssertLogBufferNoErrorBundle(t *testing.T, buf *bytes.Buffer) {
	expected := `┌ Run step 01-step.sh
└ Run step 01-step.sh

┌ Run step 02-step.sh
└ Run step 02-step.sh`

	out := prepareAndLogBungleOutput(t, buf)

	require.Equal(t, strings.TrimSpace(expected), out, "log buffer should contain")
}

func AssertLogBufferBundleWithInfo(t *testing.T, buf *bytes.Buffer) {
	expected := `┌ Run step 01-step.sh
│ Capture info
└ Run step 01-step.sh

┌ Run step 02-step.sh
└ Run step 02-step.sh`

	out := prepareAndLogBungleOutput(t, buf)

	require.Equal(t, strings.TrimSpace(expected), out, "log buffer should contain")
}

func AssertLogBufferWithErrorBundle(t *testing.T, buf *bytes.Buffer) {
	out := prepareAndLogBungleOutput(t, buf)

	// Step headers are emitted by the process logger and always come in order.
	headers := []string{
		"┌ Run step 01-step.sh",
		"└ Run step 01-step.sh",
		"┌ Run step 02-step.sh",
		"└ Run step 02-step.sh FAILED",
		"┌ Run step 02-step.sh, retry attempt #1 of 10",
		"└ Run step 02-step.sh, retry attempt #1 of 10 FAILED",
		"┌ Run step 02-step.sh, retry attempt #2 of 10",
		"└ Run step 02-step.sh, retry attempt #2 of 10 FAILED",
		"┌ Run step 02-step.sh, retry attempt #3 of 10",
		"└ Run step 02-step.sh, retry attempt #3 of 10 FAILED",
	}

	rest := out
	for _, h := range headers {
		idx := strings.Index(rest, h)
		require.GreaterOrEqual(t, idx, 0, "should contain header %q after previous headers, got:\n%s", h, out)
		rest = rest[idx+len(h):]
	}

	// Stdout and stderr of the bundle arrive over separate channels, so the
	// relative order of stream lines is not deterministic (e.g. the stderr
	// retry message may land between stdout lines); assert presence only.
	// The captured step output is logged at error level, which the compact
	// renderer prints as plain lines (no │ gutter, unlike info-level lines).
	//
	// Xtrace lines are asserted without their `+ `/`++ ` PS4 prefix: bash
	// writes the prefix as a separate write(2), and on the cli-ssh sudo path
	// (ssh -tt merges the streams into one pty, stderr is relayed through the
	// entrypoint's async `tee`) a stdout line can land between the prefix and
	// the command text, splitting the xtrace line right after the prefix.
	expects := map[string]string{
		"step output":   `second step`,
		"step failure":  `oops! failure!`,
		"retry message": `Failed to execute step /var/lib/bashible/bundle_steps/02-step.sh ... retry in 2 seconds.`,

		"first debug content": `export TERM=xterm-256color`,

		"echo debug content": `echo 'second step'`,
	}

	for name, content := range expects {
		require.Contains(t, out, strings.TrimSpace(content), "should contain ", name)
	}
}
