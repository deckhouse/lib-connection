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
	"errors"
	"io"
	"net"

	"github.com/name212/govalue"
)

type PresentCloseHandler func(isPresent bool)

func callPresentHandlers(isPresent bool, presentHandlers ...PresentCloseHandler) {
	for _, p := range presentHandlers {
		p(isPresent)
	}
}

func SafeClose(conn io.Closer, presentHandlers ...PresentCloseHandler) error {
	if govalue.Nil(conn) {
		callPresentHandlers(false, presentHandlers...)
		return nil
	}

	callPresentHandlers(true, presentHandlers...)

	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}

	return nil
}
