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

	errorsCount int
}

func newKepAliveChecker(client *Client, sleep time.Duration, maxErrors int) *keepAliveChecker {
	return &keepAliveChecker{
		client:    client,
		sleep:     sleep,
		maxErrors: maxErrors,
	}
}

func (c *keepAliveChecker) Check() error {
	err := c.checkClientAlive()

	if err != nil {
		return c.handleClientAliveFailed(err)
	}

	c.sendAliveToSessions()

	c.debug("success. Sleep %s before next request", c.sleep.String())
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
			c.debug("self session close failed: %v", err)
		}
	}()

	if err := c.sendKeepAlive(sess); err != nil {
		return fmt.Errorf("Cannot send to self session failed: %w", err)
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

func (c *keepAliveChecker) debug(format string, a ...any) {
	debugPrefix := fmt.Sprintf("Keepalive to %s ", c.client.sessionClient.String())
	format = debugPrefix + format
	c.client.debug(format, a...)
}

func (c *keepAliveChecker) handleClientAliveFailed(err error) error {
	c.debug("CheckClientAlive failed: %v", err)

	if c.errorsCount > c.maxErrors {
		c.debug("Too many errors %s encountered. Restart client and and exit keepalive", c.maxErrors)
		return errKeepExited
	}

	c.errorsCount++

	if errors.Is(err, errKeepAliveSessionCreate) {
		c.debug("failed: %v. Sleep %s before next attempt", err, c.sleep.String())
		time.Sleep(c.sleep)
	}

	return nil
}
