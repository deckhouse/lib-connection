package config

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"strings"
	"testing"

	gossh "github.com/deckhouse/lib-gossh"
	"github.com/stretchr/testify/require"
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

func intPtr(i int) *int {
	return &i
}
