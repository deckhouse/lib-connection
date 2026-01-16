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

package gossh

import (
	"errors"
	"fmt"
	"math/rand"
	"time"

	gossh "github.com/deckhouse/lib-gossh"
	"github.com/name212/govalue"
)

var (
	errKeepAliveSessionCreate = fmt.Errorf("Cannot create self keepalive session")
	errKeepExited             = fmt.Errorf("All keepalive attempts failed")
)

type keepAliveChecker struct {
	client    *Client
	sleep     time.Duration
	maxErrors int

	id          int
	errorsCount int
}

func newKepAliveChecker(client *Client, sleep time.Duration, maxErrors int) *keepAliveChecker {
	id := rand.New(rand.NewSource(time.Now().UnixNano())).Int()
	return &keepAliveChecker{
		client:    client,
		sleep:     sleep,
		maxErrors: maxErrors,
		id:        id,
	}
}

func (c *keepAliveChecker) Check() error {
	c.debug("do next check...")

	err := c.checkClientAlive()

	if err != nil {
		return c.handleClientAliveFailed(err)
	}

	c.sendAliveToSessions()

	c.debug("success. Sleep %s before next check", c.sleep.String())
	time.Sleep(c.sleep)

	return nil
}

func (c *keepAliveChecker) sendKeepAlive(sess *gossh.Session) error {
	_, err := sess.SendRequest("keepalive@openssh.com", false, nil)
	return err
}

func (c *keepAliveChecker) checkClientAlive() error {
	sess, err := c.client.sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("%w: %w", errKeepAliveSessionCreate, err)
	}

	defer func() {
		if err := sess.Close(); err != nil {
			c.debug("client self check session close failed: %v", err)
		}
	}()

	if err := c.sendKeepAlive(sess); err != nil {
		return fmt.Errorf("Cannot send to client self check session failed: %w", err)
	}

	return nil
}

func (c *keepAliveChecker) sendAliveToSessions() {
	for indx, registeredSession := range c.client.sshSessionsList {
		if govalue.Nil(registeredSession) {
			c.client.UnregisterSession(registeredSession)
			continue
		}

		if err := c.sendKeepAlive(registeredSession); err != nil {
			c.debug("%s to registered session %d failed: %v", indx, err)
		}
	}
}

func (c *keepAliveChecker) handleClientAliveFailed(err error) error {
	c.errorsCount++

	if c.errorsCount > c.maxErrors {
		c.debug("too many errors %d encountered. Last err: '%v'. Exit", c.maxErrors, err)
		return errKeepExited
	}

	if errors.Is(err, errKeepAliveSessionCreate) {
		c.debug("failed: '%v'. Error count %d. Sleep %s before next attempt", err, c.errorsCount, c.sleep.String())
		time.Sleep(c.sleep)
	}

	return nil
}

func (c *keepAliveChecker) debug(format string, a ...any) {
	debugPrefix := fmt.Sprintf("Keepalive[%d] to %s ", c.id, c.client.sessionClient.String())
	format = debugPrefix + format
	c.client.settings.Logger().DebugF(format, a...)
}
