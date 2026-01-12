// Copyright 2021 Flant JSC
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
	"os/exec"
	"strings"
	"time"

	ssh "github.com/deckhouse/lib-connection/pkg"
	"github.com/deckhouse/lib-connection/pkg/settings"
	"github.com/deckhouse/lib-connection/pkg/ssh/session"
	"github.com/deckhouse/lib-dhctl/pkg/retry"
)

var defaultAvailabilityOpts = []retry.ParamsBuilderOpt{
	retry.WithAttempts(50),
	retry.WithWait(5 * time.Second),
}

type CommandConsumer func(*session.Session, string) ssh.Command

type Check struct {
	settings settings.Settings

	Session       *session.Session
	createCommand CommandConsumer
	delay         time.Duration
}

func NewCheck(createCommand CommandConsumer, sess *session.Session, sett settings.Settings) *Check {
	return &Check{
		Session:       sess,
		createCommand: createCommand,
		settings:      sett,
	}
}

func (c *Check) WithDelaySeconds(seconds int) ssh.Check {
	c.delay = time.Duration(seconds) * time.Second
	return c
}

func (c *Check) AwaitAvailability(ctx context.Context, loopParams retry.Params) error {
	if c.Session.Host() == "" {
		return fmt.Errorf("Empty host for connection received")
	}

	select {
	case <-time.After(c.delay):
	case <-ctx.Done():
		return ctx.Err()
	}

	logger := c.settings.Logger()
	retryParams := retry.SafeCloneOrNewParams(loopParams, defaultAvailabilityOpts...).
		WithLogger(logger).
		WithName("Waiting for SSH connection")

	return retry.NewLoopWithParams(retryParams).RunContext(ctx, func() error {
		host := c.Session.Host()
		logger.InfoF("Try to connect to host: %v", host)

		output, err := c.ExpectAvailable(ctx)
		if err == nil {
			logger.InfoF("Successfully connected to host: %v", host)
			return nil
		}

		target := c.Session.Host()

		logger.InfoF("Connection attempt failed to host: %v", target)

		c.Session.ChoiceNewHost()

		return fmt.Errorf("SSH error: %s\nSSH connect failed to %s: %s", err.Error(), target, string(output))
	})
}

func (c *Check) CheckAvailability(ctx context.Context) error {
	if c.Session.Host() == "" {
		return fmt.Errorf("Empty host for connection received")
	}

	logger := c.settings.Logger()

	logger.InfoF("Try to connect to %v host", c.Session.Host())
	output, err := c.ExpectAvailable(ctx)
	if err != nil {
		logger.InfoF(string(output))
		return err
	}
	return nil
}

func (c *Check) ExpectAvailable(ctx context.Context) ([]byte, error) {
	cmd := c.createCommand(c.Session, "echo SUCCESS")
	cmd.Cmd(ctx)

	output, _, err := cmd.Output(ctx)
	if err != nil {
		var stderr []byte
		if ee := errors.Unwrap(err); ee != nil {
			var exitErr *exec.ExitError
			if errors.As(ee, &exitErr) && len(exitErr.Stderr) > 0 {
				stderr = exitErr.Stderr
			}
		}
		if len(stderr) == 0 {
			stderr = []byte(err.Error())
		}

		return stderr, err
	}

	if strings.Contains(string(output), "SUCCESS") {
		return nil, nil
	}

	return output, fmt.Errorf("SSH command output should contain \"SUCCESS\", error: %w", err)
}

func (c *Check) String() string {
	return c.Session.String()
}
