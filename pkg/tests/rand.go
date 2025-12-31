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
	"crypto/sha256"
	"fmt"
	mathrand "math/rand"
	"slices"
	"strings"
	"time"
)

const (
	portRangeStart = 22000
	portRangeEnd   = 29999
)

var (
	lettersRunes  = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	passwordRunes = append(
		append([]rune{}, lettersRunes...),
		[]rune(" %!@#$&^*.,/")...,
	)
)

func RandRange(min, max int) int {
	return randRange(getRand(), min, max)
}

func RandPort() int {
	return RandRange(portRangeStart, portRangeEnd)
}

func RandPortExclude(exclude []int) int {
	return RandRangeExclude(portRangeStart, portRangeEnd, exclude)
}

func GenerateID(names ...string) string {
	if len(names) == 0 {
		names = make([]string, 0, 1)
	}

	names = append(names, randString(12, lettersRunes))
	sumString := strings.Join(names, "/")
	sum := sha256Encode(sumString)

	return fmt.Sprintf("%.12s", sum)
}

func RandRangeExclude(min, max int, exclude []int) int {
	randomizer := getRand()
	for i := 0; i < 100; i++ {
		v := randRange(randomizer, min, max)
		if slices.Contains(exclude, v) {
			continue
		}

		return v
	}

	panic("random range exclude failed after 100 iterations")
}

func RandInvalidPortExclude(_ []int) int {
	return 0
}

func RandPassword(n int) string {
	return randString(n, passwordRunes)
}

func randString(n int, letters []rune) string {
	randomizer := getRand()

	b := make([]rune, n)
	for i := range b {
		b[i] = letters[randomizer.Intn(len(letters))]
	}

	return string(b)
}

func getRand() *mathrand.Rand {
	return mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
}

func randRange(randomizer *mathrand.Rand, min, max int) int {
	return randomizer.Intn(max-min) + min
}

func sha256Encode(input string) string {
	hasher := sha256.New()

	hasher.Write([]byte(input))

	return fmt.Sprintf("%x", hasher.Sum(nil))
}
