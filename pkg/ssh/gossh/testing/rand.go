package ssh_testing

import (
	"crypto/sha256"
	"fmt"
	mathrand "math/rand"
	"slices"
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

func GenerateID(name string) string {
	sumString := fmt.Sprintf("%s/%s", name, randString(12, lettersRunes))
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
