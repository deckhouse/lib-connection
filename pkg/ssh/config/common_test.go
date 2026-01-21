package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	mathrand "math/rand"
	"strings"
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/log"
	gossh "github.com/deckhouse/lib-gossh"
	"github.com/stretchr/testify/require"

	"github.com/deckhouse/lib-connection/pkg/settings"
)

func marshalKey(privateKey *rsa.PrivateKey, passphrase string) (*pem.Block, error) {
	if len(passphrase) == 0 {
		return gossh.MarshalPrivateKey(privateKey, "")
	}

	return gossh.MarshalPrivateKeyWithPassphrase(privateKey, "", []byte(passphrase))
}

// helper func to generate SSH keys
func generateKey(t *testing.T, passphrase string) string {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "error generating rsa key")

	privateKeyPem, err := marshalKey(privateKey, passphrase)
	require.NoError(t, err, "error marshaling rsa key")

	pemBytes := pem.EncodeToMemory(privateKeyPem)

	return strings.TrimRight(string(pemBytes), "\n")
}

func testSettings() settings.Settings {
	const isDebug = true
	return settings.NewBaseProviders(settings.ProviderParams{
		LoggerProvider: log.SimpleLoggerProvider(
			log.NewInMemoryLoggerWithParent(
				log.NewPrettyLogger(log.LoggerOptions{IsDebug: isDebug}),
			),
		),
		IsDebug: isDebug,
	})
}

type connectionConfigAssertParams struct {
	hasErrorContains string
	err              error
	got              *ConnectionConfig
	expected         *ConnectionConfig
	logger           log.Logger
}

func assertConnectionConfig(t *testing.T, params connectionConfigAssertParams) {
	err := params.err
	cfg := params.got

	if params.hasErrorContains != "" {
		require.Error(t, err, "expected error but got none")
		// show log msg for human observability
		params.logger.ErrorF("%v", err)
		require.Contains(t, err.Error(), params.hasErrorContains, "error should contain")
		require.Nil(t, cfg, "cfg should be nil")
		return
	}

	require.NoError(t, err, "expected no error but got one")

	if len(cfg.Config.PrivateKeys) > 0 {
		trimmedKeys := make([]AgentPrivateKey, 0, len(cfg.Config.PrivateKeys))

		for _, key := range cfg.Config.PrivateKeys {
			trimmedKeys = append(trimmedKeys, AgentPrivateKey{
				Key:        strings.TrimRight(key.Key, "\n"),
				Passphrase: key.Passphrase,
			})
		}

		cfg.Config.PrivateKeys = trimmedKeys
	}

	require.Equal(t, params.expected, cfg, "config should be equal")
}

// TODO move to test helpers packet
const (
	tmpGlobalDirName = "test-lib-connection"
)

var (
	lettersRunes  = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	passwordRunes = append(
		append([]rune{}, lettersRunes...),
		[]rune(" %!@#$&^*.,/")...,
	)
)

func GenerateID(names ...string) string {
	if len(names) == 0 {
		names = make([]string, 0, 1)
	}

	names = append(names, randString(12, lettersRunes))
	sumString := strings.Join(names, "/")
	sum := sha256Encode(sumString)

	return fmt.Sprintf("%.12s", sum)
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

func sha256Encode(input string) string {
	hasher := sha256.New()

	hasher.Write([]byte(input))

	return fmt.Sprintf("%x", hasher.Sum(nil))
}
