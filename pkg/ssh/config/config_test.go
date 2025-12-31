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

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetConfigDefaults(t *testing.T) {
	assertPort := func(t *testing.T, port *int, msg string) {
		require.NotNil(t, port, msg)
		require.Equal(t, *port, DefaultPort, msg)
	}

	cfg := &Config{}
	cfg.FillDefaults()

	assertPort(t, cfg.Port, "port")
	assertPort(t, cfg.BastionPort, "bastion port")
}

func TestConfigClone(t *testing.T) {
	assertCloned := func(t *testing.T, cfg *Config, cpy *Config) {
		require.False(t, cfg == cpy, "clone should different object")
		require.Equal(t, cfg, cpy, "should be equal")
	}

	assertNotAffected := func(t *testing.T, cfg *Config, cpy *Config, mutator func(*Config)) {
		mutator(cpy)
		require.NotEqual(t, cfg, cpy, "mutate clone not affect object for copy")
	}

	t.Run("full copy", func(t *testing.T) {
		cfg := &Config{
			Mode: Mode{
				ForceLegacy: true,
				ForceModern: false,
			},

			User:         "user",
			Port:         intPtr(2220),
			SudoPassword: "not secure",

			PrivateKeys: []AgentPrivateKey{
				{
					Key:        "content",
					Passphrase: "not secure key",
					IsPath:     false,
				},

				{
					Key:    "/tmp/notexists",
					IsPath: true,
				},
			},

			BastionHost:     "127.0.0.1",
			BastionPort:     intPtr(2201),
			BastionUser:     "bastion",
			BastionPassword: "not secure bastion",

			ExtraArgs: "a,b",
		}

		cpy := cfg.Clone()

		assertCloned(t, cfg, cpy)
		assertNotAffected(t, cfg, cpy, func(c *Config) {
			c.ForceModern = true
			c.Port = intPtr(2222)
			c.PrivateKeys[0].Key = "/tmp/notexists2"
			c.PrivateKeys[0].IsPath = true
			c.PrivateKeys[1].Passphrase = "not secure key2"
			*c.BastionPort = 3333
		})
	})

	t.Run("private keys", func(t *testing.T) {
		t.Run("private keys nil", func(t *testing.T) {
			cfgNilKeys := &Config{
				User:         "user",
				Port:         intPtr(2230),
				SudoPassword: "not secure",
				BastionPort:  intPtr(2231),
			}

			cfgNilKeysCpy := cfgNilKeys.Clone()

			assertCloned(t, cfgNilKeys, cfgNilKeysCpy)
		})

		t.Run("private keys append", func(t *testing.T) {
			cfgKeys := &Config{
				User:         "user",
				Port:         intPtr(2235),
				SudoPassword: "not secure",
				BastionPort:  intPtr(2236),
				PrivateKeys: []AgentPrivateKey{
					{
						Key:        "content",
						Passphrase: "not secure key",
						IsPath:     false,
					},
				},
			}

			cfgKeysCpy := cfgKeys.Clone()

			assertCloned(t, cfgKeys, cfgKeysCpy)
			assertNotAffected(t, cfgKeys, cfgKeysCpy, func(c *Config) {
				c.PrivateKeys = append(c.PrivateKeys, AgentPrivateKey{
					Key:    "/tmp/notexists",
					IsPath: true,
				})
			})
		})
	})

	t.Run("nil port", func(t *testing.T) {
		cfgNilPort := &Config{
			User:         "user",
			SudoPassword: "not secure",

			BastionPort: intPtr(2223),
		}

		cfgNilPortCpy := cfgNilPort.Clone()

		assertCloned(t, cfgNilPort, cfgNilPortCpy)
		assertNotAffected(t, cfgNilPort, cfgNilPortCpy, func(c *Config) {
			c.Port = intPtr(2225)
			*c.BastionPort = 3334
		})
	})

	t.Run("nil bastion port", func(t *testing.T) {
		cfgNilBastionPort := &Config{
			User:         "user",
			Port:         intPtr(2228),
			SudoPassword: "not secure",
		}

		cfgNilBastionPortCpy := cfgNilBastionPort.Clone()

		assertCloned(t, cfgNilBastionPort, cfgNilBastionPortCpy)
		assertNotAffected(t, cfgNilBastionPort, cfgNilBastionPortCpy, func(c *Config) {
			*c.Port = 2229
			c.BastionPort = intPtr(3335)
		})
	})
}
