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

package utils

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/log"
	"github.com/name212/govalue"

	connection "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/utils/tar"
)

var (
	ErrTimeout = errors.New("Timeout step running")
)

type (
	CommandKiller     func(connection.Command)
	CommandPreparator func(connection.Command)
	BundleOpt         func(*Bundle)
)

func BundleWithStepHeader(r *regexp.Regexp) BundleOpt {
	return func(b *Bundle) {
		b.stepHeaderRegex = r
	}
}

func BundleWithNoLogStepOutOnError(v bool) BundleOpt {
	return func(b *Bundle) {
		b.noLogStepOutOnError = v
	}
}

func BundleWithShouldInfoOutChecker(c connection.BundlerShouldInfoOutChecker) BundleOpt {
	return func(b *Bundle) {
		b.shouldInfoOutCheck = c
	}
}

func BundleWithStepsDelimiter(d string) BundleOpt {
	return func(b *Bundle) {
		b.stepsDelimiter = d
	}
}

func BundleWithRetries(r int) BundleOpt {
	return func(b *Bundle) {
		if r > 0 {
			b.retries = r
		}
	}
}

func BundleWithCommandKiller(k CommandKiller) BundleOpt {
	return func(b *Bundle) {
		b.commandKiller = k
	}
}

func BundleWithCommandPreparator(p CommandPreparator) BundleOpt {
	return func(b *Bundle) {
		b.commandPreparator = p
	}
}

func UserBundleOptsOrBashible(inputOpts ...connection.BundlerOption) ([]BundleOpt, error) {
	userOpts := make([]connection.BundlerOption, len(inputOpts))
	copy(userOpts, inputOpts)

	if len(userOpts) == 0 {
		userOpts = bashibleBundleOpts()
	}

	return convertBundleOption(userOpts...)
}

type Bundle struct {
	sett   settings.Settings
	client connection.SSHClient

	scriptPath string
	args       []string

	stepHeaderRegex    *regexp.Regexp
	shouldInfoOutCheck connection.BundlerShouldInfoOutChecker
	noLogStepOutOnError bool
	stepsDelimiter      string
	retries             int
	commandKiller       CommandKiller
	commandPreparator   CommandPreparator
}

func NewBundle(sett settings.Settings, client connection.SSHClient, scriptPath string, args []string, opts ...BundleOpt) (*Bundle, error) {
	b := &Bundle{
		sett:       sett,
		client:     client,
		scriptPath: scriptPath,
		args:       args,
		retries:    10,
	}

	for _, opt := range opts {
		opt(b)
	}

	if b.stepsDelimiter == "" {
		return nil, fmt.Errorf("no steps delimiter")
	}

	if govalue.Nil(b.stepHeaderRegex) {
		return nil, fmt.Errorf("no step header regex")
	}

	if govalue.Nil(b.shouldInfoOutCheck) {
		b.shouldInfoOutCheck = shouldNotInfoOutChecker
	}

	return b, nil
}

func (b *Bundle) Execute(ctx context.Context, parentDir, bundleDir string) ([]byte, error) {
	bundleName := fmt.Sprintf("bundle-%s.tar", time.Now().Format("20060102-150405"))
	bundleLocalFilepath := filepath.Join(b.sett.TmpDir(), bundleName)

	// tar cpf bundle.tar -C /tmp/dhctl.1231qd23/var/lib bashible
	err := tar.CreateTar(bundleLocalFilepath, parentDir, bundleDir)
	if err != nil {
		return nil, fmt.Errorf("tar bundle: %v", err)
	}

	b.sett.RegisterOnShutdown(
		"Delete bashible bundle folder",
		func() { _ = os.Remove(bundleLocalFilepath) },
	)

	nodeTmp := b.sett.NodeTmpDir()

	// upload to node's deckhouse tmp directory
	err = b.client.File().Upload(ctx, bundleLocalFilepath, nodeTmp)
	if err != nil {
		return nil, fmt.Errorf("upload: %v", err)
	}

	// sudo:
	// tar xpof ${app.DeckhouseNodeTmpPath}/bundle.tar -C /var/lib && /var/lib/bashible/bashible.sh args...
	tarCmdline := fmt.Sprintf(
		"tar xpof %s/%s -C /var/lib && /var/lib/%s/%s %s",
		nodeTmp,
		bundleName,
		bundleDir,
		b.scriptPath,
		strings.Join(b.args, " "),
	)
	bundleCmd := b.client.Command(tarCmdline)
	bundleCmd.Sudo(ctx)

	logger := b.sett.Logger()
	processLogger := logger.ProcessLogger()

	handler := newOutputHandler(b, bundleCmd, logger, processLogger)
	bundleCmd.WithStdoutHandler(handler.getHandlerFunc())

	if b.commandPreparator != nil {
		b.commandPreparator(bundleCmd)
	}

	err = bundleCmd.Run(ctx)
	if err != nil {
		if handler.lastStep != "" {
			processLogger.ProcessFail()
		}

		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// exitErr.Stderr is set in the "os/exec".Cmd.Output method from the Golang standard library.
			// But we call the "os/exec".Cmd.Wait method, which does not set the Stderr field.
			// We can reuse the exec.ExitError type when handling errors.
			exitErr.Stderr = bundleCmd.StderrBytes()
		}

		err = fmt.Errorf("execute bundle: %w", err)
	} else {
		processLogger.ProcessEnd()
	}

	if handler.hasStepTimeout {
		return bundleCmd.StdoutBytes(), ErrTimeout
	}

	return bundleCmd.StdoutBytes(), err
}

func (b *Bundle) killCommand(cmd connection.Command) {
	if govalue.Nil(cmd) {
		return
	}

	if govalue.Nil(b.commandKiller) {
		return
	}

	b.commandKiller(cmd)
}

type outputHandler struct {
	cmd           connection.Command
	processLogger log.ProcessLogger
	logger        log.Logger
	bundler       *Bundle

	stepLogs       []string
	lastStep       string
	failsCounter   int
	hasStepTimeout bool
}

func newOutputHandler(bundler *Bundle, cmd connection.Command, logger log.Logger, processLogger log.ProcessLogger) *outputHandler {
	return &outputHandler{
		bundler:       bundler,
		cmd:           cmd,
		logger:        logger,
		processLogger: processLogger,

		stepLogs: make([]string, 0),
	}
}

func (h *outputHandler) getHandlerFunc() func(string) {
	return func(line string) {
		h.handle(line)
	}
}

func (h *outputHandler) handle(l string) {
	if l == h.bundler.stepsDelimiter {
		return
	}

	if !h.bundler.stepHeaderRegex.MatchString(l) {
		outString := l
		doLog := h.logger.DebugF
		if infoOut := h.bundler.shouldInfoOutCheck(l); infoOut != "" {
			outString = infoOut
			doLog = h.logger.InfoF
		}

		h.stepLogs = append(h.stepLogs, outString)
		doLog("%s", outString)
		return
	}

	match := h.bundler.stepHeaderRegex.FindStringSubmatch(l)
	stepName := match[1]

	if h.lastStep == stepName {
		logMessage := strings.Join(h.stepLogs, "\n")
		switch {
		case h.bundler.noLogStepOutOnError && h.failsCounter == 0:
			h.logger.ErrorF("%s", logMessage)
		case h.bundler.noLogStepOutOnError && h.failsCounter > 0:
			h.logger.ErrorF("Run step %s finished with error^^^\n", stepName)
			h.logger.DebugF("%s", logMessage)
		default:
			h.logger.ErrorF("%s", logMessage)
		}
		h.failsCounter++
		h.stepLogs = h.stepLogs[:0]
		if h.failsCounter > h.bundler.retries {
			h.hasStepTimeout = true
			h.bundler.killCommand(h.cmd)
			return
		}

		h.processLogger.ProcessFail()
		stepName = fmt.Sprintf("%s, retry attempt #%d of %d", stepName, h.failsCounter, h.bundler.retries)
	} else if h.lastStep != "" {
		h.stepLogs = make([]string, 0)
		h.processLogger.ProcessEnd()
		h.failsCounter = 0
	}

	h.processLogger.ProcessStart("Run step " + stepName)
	h.lastStep = match[1]
}

var (
	bashibleStepsHeaderRegexp      = regexp.MustCompile("^=== Step: /var/lib/bashible/bundle_steps/(.*)$")
	bashibleStepOutputHeaderRegexp = regexp.MustCompile("^=== Step output: (.*)$")
)

func shouldNotInfoOutChecker(l string) string {
	return ""
}

func bashibleShouldInfoOutChecker(l string) string {
	if bashibleStepOutputHeaderRegexp.MatchString(l) {
		match := bashibleStepOutputHeaderRegexp.FindStringSubmatch(l)
		if len(match) >= 2 {
			return match[1]
		}
	}

	return ""
}

func bashibleBundleOpts() []connection.BundlerOption {
	return []connection.BundlerOption{
		connection.BundlerWithStepHeaderRegex(bashibleStepsHeaderRegexp),
		connection.BundlerWithStepDelimiter("==="),
		connection.BundlerWithRetries(10),
		connection.BundlerWithShouldInfoOutChecker(bashibleShouldInfoOutChecker),
	}
}

func convertBundleOption(opts ...connection.BundlerOption) ([]BundleOpt, error) {
	if len(opts) == 0 {
		return nil, nil
	}

	options := connection.BundlerOptions{}
	for _, opt := range opts {
		opt(&options)
	}

	if err := options.IsValid(); err != nil {
		return nil, err
	}

	return []BundleOpt{
		BundleWithRetries(options.Retries),
		BundleWithStepHeader(options.StepHeaderRegex),
		BundleWithStepsDelimiter(options.StepsDelimiter),
		BundleWithNoLogStepOutOnError(options.NoLogStepOutOnError),
		BundleWithShouldInfoOutChecker(options.ShouldInfoOutChecker),
	}, nil
}
