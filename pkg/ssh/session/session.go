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

package session

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

type Input struct {
	User            string
	Port            string
	BastionHost     string
	BastionPort     string
	BastionUser     string
	BastionPassword string
	ExtraArgs       string
	AvailableHosts  []Host
	BecomePass      string
}

type AgentSettings struct {
	PrivateKeys []AgentPrivateKey

	// runtime
	AuthSock string
}

type AgentPrivateKey struct {
	Key        string
	Passphrase string
}

func (s *AgentSettings) AuthSockEnv() string {
	if s.AuthSock != "" {
		return fmt.Sprintf("SSH_AUTH_SOCK=%s", s.AuthSock)
	}
	return ""
}

func (s *AgentSettings) Clone() *AgentSettings {
	return &AgentSettings{
		AuthSock:    s.AuthSock,
		PrivateKeys: append(make([]AgentPrivateKey, 0), s.PrivateKeys...),
	}
}

// TODO rename to Settings
// Session is used to store ssh settings
type Session struct {
	// input
	User            string
	Port            string
	BastionHost     string
	BastionPort     string
	BastionUser     string
	BastionPassword string
	ExtraArgs       string
	BecomePass      string

	AgentSettings *AgentSettings

	lock           sync.RWMutex
	host           string
	availableHosts []Host
	remainingHosts []Host
}

type Host struct {
	Host string
	Name string
}

func (h *Host) String() string {
	name := h.Name
	if name != "" {
		name = fmt.Sprintf("%s: ", name)
	}
	return fmt.Sprintf("%s%s", name, h.Host)
}

type SortByName []Host

func (h SortByName) Len() int { return len(h) }
func (h SortByName) Less(i, j int) bool {
	if h[i].Name == h[j].Name {
		return h[i].Host < h[j].Host
	} else {
		return h[i].Name < h[j].Name
	}
}
func (h SortByName) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func NewSession(input Input) *Session {
	s := &Session{
		User:            input.User,
		Port:            input.Port,
		BastionHost:     input.BastionHost,
		BastionPort:     input.BastionPort,
		BastionUser:     input.BastionUser,
		ExtraArgs:       input.ExtraArgs,
		BecomePass:      input.BecomePass,
		BastionPassword: input.BastionPassword,
	}

	s.SetAvailableHosts(input.AvailableHosts)

	return s
}

func (s *Session) Host() string {
	defer s.lock.RUnlock()
	s.lock.RLock()
	return s.host
}

// ChoiceNewHost choice new host for connection
func (s *Session) ChoiceNewHost() {
	defer s.lock.Unlock()
	s.lock.Lock()

	s.selectNewHost()
}

func (s *Session) AddAvailableHosts(hosts ...Host) {
	defer s.lock.Unlock()
	s.lock.Lock()

	availableHostsMap := make(map[string]string, len(s.availableHosts))

	for _, host := range s.availableHosts {
		availableHostsMap[host.Host] = host.Name
	}

	for _, host := range hosts {
		availableHostsMap[host.Host] = host.Name
	}

	availableHosts := make([]Host, 0, len(availableHostsMap))

	for key, value := range availableHostsMap {
		availableHosts = append(availableHosts, Host{Host: key, Name: value})
	}

	sort.Sort(SortByName(availableHosts))
	s.availableHosts = availableHosts

	s.resetUsedHosts()
	s.selectNewHost()
}

func (s *Session) RemoveAvailableHosts(hosts ...Host) {
	defer s.lock.Unlock()
	s.lock.Lock()

	availableHostsMap := make(map[string]string, len(s.availableHosts))

	for _, host := range s.availableHosts {
		availableHostsMap[host.Host] = host.Name
	}

	for _, host := range hosts {
		delete(availableHostsMap, host.Host)
	}

	availableHosts := make([]Host, 0, len(availableHostsMap))

	for key, value := range availableHostsMap {
		availableHosts = append(availableHosts, Host{Host: key, Name: value})
	}

	sort.Sort(SortByName(availableHosts))
	s.availableHosts = availableHosts

	s.resetUsedHosts()
	s.selectNewHost()
}

// SetAvailableHosts
// Set Available hosts. Current host can choice
func (s *Session) SetAvailableHosts(hosts []Host) {
	defer s.lock.Unlock()
	s.lock.Lock()

	s.availableHosts = make([]Host, len(hosts))
	copy(s.availableHosts, hosts)

	s.resetUsedHosts()
	s.selectNewHost()
}

func (s *Session) AvailableHosts() []Host {
	s.lock.RLock()
	defer s.lock.RUnlock()

	return append(make([]Host, 0), s.availableHosts...)
}

func (s *Session) CountHosts() int {
	defer s.lock.RUnlock()
	s.lock.RLock()

	return len(s.availableHosts)
}

// RemoteAddress returns host or username@host
func (s *Session) RemoteAddress() string {
	defer s.lock.RUnlock()
	s.lock.RLock()

	addr := s.host
	if s.User != "" {
		addr = s.User + "@" + addr
	}
	return addr
}

func (s *Session) String() string {
	defer s.lock.RUnlock()
	s.lock.RLock()

	builder := strings.Builder{}
	builder.WriteString("ssh ")

	if s.BastionHost != "" {
		builder.WriteString("-J ")
		if s.BastionUser != "" {
			builder.WriteString(fmt.Sprintf("%s@%s", s.BastionUser, s.BastionHost))
		} else {
			builder.WriteString(s.BastionHost)
		}
		if s.BastionPort != "" {
			builder.WriteString(fmt.Sprintf(":%s", s.BastionPort))
		}
		builder.WriteString(" ")
	}

	if s.User != "" {
		builder.WriteString(fmt.Sprintf("%s@%s", s.User, s.host))
	} else {
		builder.WriteString(s.host)
	}

	if s.Port != "" && s.Port != "22" {
		builder.WriteString(fmt.Sprintf(" -p %s", s.Port))
	}

	return builder.String()
}

func (s *Session) Copy() *Session {
	defer s.lock.RUnlock()
	s.lock.RLock()

	ses := &Session{}

	ses.Port = s.Port
	ses.User = s.User
	ses.BastionHost = s.BastionHost
	ses.BastionPort = s.BastionPort
	ses.BastionUser = s.BastionUser
	ses.BastionPassword = s.BastionPassword
	ses.ExtraArgs = s.ExtraArgs
	ses.BecomePass = s.BecomePass
	ses.host = s.host

	if s.AgentSettings != nil {
		ses.AgentSettings = s.AgentSettings.Clone()
	}

	ses.availableHosts = make([]Host, len(s.availableHosts))
	copy(ses.availableHosts, s.availableHosts)

	ses.resetUsedHosts()

	return ses
}

// resetUsedHosts if all available host is used this function reset
func (s *Session) resetUsedHosts() {
	s.remainingHosts = make([]Host, len(s.availableHosts))
	copy(s.remainingHosts, s.availableHosts)
	s.host = ""
}

// selectNewHost selects new host from available and updates remaining hosts
func (s *Session) selectNewHost() {
	if len(s.availableHosts) == 0 {
		s.host = ""
		return
	}

	hosts := make([]Host, len(s.availableHosts))
	copy(hosts, s.availableHosts)
	hostIndx := 0
	if s.host != "" {
		for i, host := range hosts {
			if host.Host == s.host {
				if i != len(hosts)-1 {
					hostIndx = i + 1
				}
				break
			}
		}
	}

	host := hosts[hostIndx]
	s.remainingHosts = hosts[:hostIndx]
	s.remainingHosts = append(s.remainingHosts, hosts[hostIndx+1:]...)

	s.host = host.Host
}

func Compare(first, second *Session) bool {
	if first == nil && second == nil {
		return true
	}

	if first == nil {
		return false
	}

	if second == nil {
		return false
	}

	if first.User != second.User {
		return false
	}

	if first.Port != second.Port {
		return false
	}

	if first.BecomePass != second.BecomePass {
		return false
	}

	if first.BastionUser != second.BastionUser {
		return false
	}

	if first.BastionHost != second.BastionHost {
		return false
	}

	if first.BastionPort != second.BastionPort {
		return false
	}

	if first.BastionPassword != second.BastionPassword {
		return false
	}

	if first.ExtraArgs != second.ExtraArgs {
		return false
	}

	firstAvailableHosts := first.AvailableHosts()
	secondAvailableHosts := second.AvailableHosts()

	if len(firstAvailableHosts) != len(secondAvailableHosts) {
		return false
	}

	firstHosts := make(map[string]struct{}, len(firstAvailableHosts))
	for _, host := range firstAvailableHosts {
		firstHosts[host.Host] = struct{}{}
	}

	for _, host := range secondAvailableHosts {
		if _, ok := firstHosts[host.Host]; !ok {
			return false
		}
	}

	return true
}

type SessionWithPrivateKeys struct {
	Session *Session
	Keys    []AgentPrivateKey
}

func CompareWithKeys(first, second *SessionWithPrivateKeys) bool {
	if first == nil && second == nil {
		return true
	}

	if first == nil {
		return false
	}

	if second == nil {
		return false
	}

	if !Compare(first.Session, second.Session) {
		return false
	}

	if len(first.Keys) != len(second.Keys) {
		return false
	}

	firstKeys := make(map[string]struct{}, len(first.Keys))

	for _, key := range first.Keys {
		firstKeys[privateKeyString(key)] = struct{}{}
	}

	for _, key := range second.Keys {
		str := privateKeyString(key)
		if _, ok := firstKeys[str]; !ok {
			return false
		}
	}

	return true
}

func privateKeyString(key AgentPrivateKey) string {
	return fmt.Sprintf("%s#%s", key.Key, key.Passphrase)
}
