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
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/deckhouse/lib-connection/pkg/settings"
)

type TestFlagsParser interface {
	InitFlags(*flag.FlagSet) (*flag.FlagSet, error)
}

type TestFlagsParserHelpProvider func(s settings.Settings, envsPrefix string) TestFlagsParser

type AssertParseFlagsHelpParams struct {
	Name          string
	Provider      TestFlagsParserHelpProvider
	ExpectedFlags int
}

func AssertParseFlagsHelp(t *testing.T, params AssertParseFlagsHelpParams) {
	oldStdErr := os.Stderr
	restoreStderr := func() {
		os.Stderr = oldStdErr
	}

	t.Cleanup(restoreStderr)

	test := ShouldNewTest(t, params.Name)

	sett := test.Settings()
	logger := test.GetLogger()

	// Create a pipe
	pr, pw, err := os.Pipe()
	require.NoError(t, err, "pipes should created")

	os.Stderr = pw

	var wg sync.WaitGroup
	wg.Add(1)

	var buf bytes.Buffer

	closed := false

	closePipes := func() {
		if closed {
			return
		}

		// hack to wait write all
		time.Sleep(3 * time.Second)

		if err := pr.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			logger.ErrorF("Error closing read pipe: %v", err)
		}

		if err := pw.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			logger.ErrorF("Error closing read pipe: %v", err)
		}

		wg.Wait()

		if err := bufio.NewWriter(&buf).Flush(); err != nil {
			logger.ErrorF("Error flushing buf: %v", err)
		}

		closed = true
	}

	t.Cleanup(closePipes)

	hasCopyErr := func(err error) bool {
		if err == nil {
			return false
		}

		if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
			return false
		}

		return true
	}

	go func() {
		defer wg.Done()
		_, err := io.Copy(&buf, pr)
		// Copy all content from the pipe reader to the buffer
		if err != nil && hasCopyErr(err) {
			logger.ErrorF("Error copying data from stderr: %v", err)
		}
	}()

	t.Cleanup(func() {
		closePipes()
		restoreStderr()
		if t.Failed() {
			out := buf.String()
			logger.InfoF("Got usage from Parse:")
			logger.InfoF("%s", out)
		}
	})

	// no use require because all stdout rewrite to buf
	assertNoError := func(t *testing.T, msg string, err error) {
		if err != nil {
			restoreStderr()
			logger.ErrorF("%s: %v", msg, err)
			t.FailNow()
		}
	}

	flagSet := flag.NewFlagSet(params.Name, flag.ContinueOnError)

	parser := params.Provider(sett, "MY_PREFIX")
	newFlagsSet, err := parser.InitFlags(flagSet)
	assertNoError(t, "Flags init failed", err)

	err = newFlagsSet.Parse([]string{"--help"})
	if !errors.Is(err, flag.ErrHelp) {
		assertNoError(t, "Flags parse failed. Should return ErrHelp", fmt.Errorf("not help: %w", err))
	}
	// stop writing
	closePipes()

	usagePrefix := fmt.Sprintf("Usage of %s:\n", params.Name)

	out := buf.String()
	if !strings.Contains(out, usagePrefix) {
		assertNoError(t, "Flags help failed", fmt.Errorf("not contains usage prefix"))
	}

	out = strings.TrimPrefix(out, usagePrefix)
	out = strings.TrimSuffix(out, "\n")

	lines := strings.Split(out, "\n")
	linesCount := len(lines)

	if linesCount != params.ExpectedFlags {
		assertNoError(
			t,
			fmt.Sprintf("Flags help failed \n%s\n", out), fmt.Errorf(
				"not contains all flags should %d  got %d", params.ExpectedFlags, linesCount,
			))
	}

	envMsgRe := regexp.MustCompile(`\(Can rewrite with MY_PREFIX_[A-Z_]+ env\)`)

	notContainsEnv := make([]string, 0)
	for _, line := range lines {
		if !envMsgRe.MatchString(line) {
			notContainsEnv = append(notContainsEnv, line)
		}
	}

	if len(notContainsEnv) > 0 {
		assertNoError(t,
			"Flags help failed",
			fmt.Errorf(
				"not contains env vars for:\n %v",
				strings.Join(notContainsEnv, "\n"),
			),
		)
	}

	logger.InfoF("Has valid help:\n%s", out)
}
