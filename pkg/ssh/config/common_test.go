package config

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
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

var (
	testConfigTemplate = `
apiVersion: dhctl.deckhouse.io/v1
kind: SSHConfig

{{ .fields }}

{{ if .keys }}
sshAgentPrivateKeys:
{{- range .keys }}
- key: |
{{ .key | indent 4}}
  {{- if .passphrase }}
  passphrase: "{{ .passphrase }}"
  {{- end }}
{{- end }}
{{- else }}
sshAgentPrivateKeys: []
{{- end }}
{{- range .hosts }}
---
apiVersion: dhctl.deckhouse.io/v1
kind: SSHHost
{{- if . }}
host: "{{ . }}"
{{- end }}
{{- end }}
`

	testConfigTemplateEngine *template.Template
)

func generateConfigWithKeys(t *testing.T, keys []AgentPrivateKey, additionalFields string, hosts ...string) string {
	var keysMap []map[string]string
	keysJson, err := json.Marshal(keys)
	require.NoError(t, err)
	err = json.Unmarshal(keysJson, &keysMap)
	require.NoError(t, err)

	if additionalFields == "" {
		additionalFields = `
sshPort: 22
sshUser: ubuntu
`
	}

	if len(hosts) == 0 {
		hosts = make([]string, 0)
	}

	var tpl bytes.Buffer
	err = testConfigTemplateEngine.Execute(&tpl, map[string]any{
		"keys":   keysMap,
		"fields": additionalFields,
		"hosts":  hosts,
	})
	require.NoError(t, err, "error executing template")
	return strings.TrimRight(tpl.String(), "\n")
}

func init() {
	var err error
	testConfigTemplateEngine, err = template.New("test_connection_config").Funcs(template.FuncMap{
		"indent": func(spaces int, v string) string {
			pad := strings.Repeat(" ", spaces)
			return pad + strings.Replace(v, "\n", "\n"+pad, -1)
		},
	}).Parse(testConfigTemplate)

	if err != nil {
		panic(err)
	}
}

func setEnvs(t *testing.T, envs map[string]string) {
	if len(envs) == 0 {
		return
	}

	forUnset := make(map[string]struct{})
	oldEnvs := make(map[string]string)

	t.Cleanup(func() {
		for k, v := range oldEnvs {
			if err := os.Setenv(k, v); err != nil {
				t.Logf("error restore env variable %s: %v", k, err)
			}
		}

		for k := range forUnset {
			if err := os.Unsetenv(k); err != nil {
				t.Logf("error unset env variable %s: %v", k, err)
			}
		}
	})

	for k, v := range envs {
		old, ok := os.LookupEnv(k)
		if ok {
			oldEnvs[k] = old
		}

		if err := os.Setenv(k, v); err != nil {
			require.NoError(t, err, "error set env variable %s", k)
		}

		if !ok {
			forUnset[k] = struct{}{}
		}
	}
}

func newTestTmpDir(t *testing.T, name string, logger log.Logger) *testTmpDir {
	id := GenerateID(name)
	localTmpDirStr := filepath.Join(os.TempDir(), tmpGlobalDirName, "test-flags", id)

	d := &testTmpDir{
		id:     id,
		tmpDir: localTmpDirStr,
		logger: logger,
		name:   name,
	}

	d.createRootDir(t)

	return d
}

func (d *testTmpDir) createRootDir(t *testing.T) {
	tmpDir := d.tmpDir

	require.NotEmpty(t, tmpDir, "tmp dir does not set")

	err := os.MkdirAll(tmpDir, 0777)
	require.NoError(t, err, "create tmp dir %s", tmpDir)
	t.Cleanup(func() {
		d.cleanup()
	})

	d.logger.InfoF("Root tmp dir %s created", tmpDir)
}

func (d *testTmpDir) createSubDir(t *testing.T, name string) string {
	tmpDir := d.tmpDir

	require.NotEmpty(t, tmpDir, "tmp dir does not set")

	path := filepath.Join(tmpDir, name)

	err := os.MkdirAll(path, 0777)
	require.NoError(t, err, "create tmp sub dir %s", path)

	d.logger.InfoF("Sub dir tmp for %s created %s", name, path)

	return path
}

func (d *testTmpDir) writeFile(t *testing.T, content string, name string) string {
	require.NotEmpty(t, d.tmpDir, "tmp dir does not set")
	if name == "" {
		name = GenerateID()
	}

	path := filepath.Join(d.tmpDir, fmt.Sprintf("%s.%s", name, d.id))
	err := os.WriteFile(path, []byte(content), 0600)
	require.NoError(t, err, "write file %s", path)

	d.logger.InfoF("File written: %s", path)

	return path
}

func (d *testTmpDir) cleanup() {
	if d.alreadyCleanup {
		return
	}

	tmpDir := d.tmpDir
	if tmpDir == "" || tmpDir == "." || tmpDir == "/" {
		return
	}

	if err := os.RemoveAll(tmpDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		d.logger.ErrorF("Cannot remove test dir '%s': %v", tmpDir, err)
		return
	}

	d.logger.InfoF("Test dir '%s' removed", tmpDir)
	d.alreadyCleanup = true
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
