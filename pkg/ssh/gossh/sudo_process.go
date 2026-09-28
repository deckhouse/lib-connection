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
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	gossh "github.com/deckhouse/lib-gossh"
)

// Signalling a command started with Sudo.
//
// sshd handles the "signal" channel request with killpg() on the process group
// of the session, using the privileges of the SSH user. The process group of a
// sudo command is "sudo -> command tree": sudo keeps the real uid of the user, so
// it receives the signal, but the command runs as root and does not. For
// signals sudo relays (TERM, INT, HUP, ...) the command may still get them from
// sudo, but SIGKILL, SIGABRT and the rest just kill sudo and leave the command
// running as an orphan.
//
// So a sudo command is signalled by running "kill" on the remote as root
// through a separate session. The wrapper started by Sudo prints a marker line
// with the process group id of the command tree and the start time of the group
// leader (from /proc/<pgid>/stat), the line is stripped from the command output
// by markerLineCapture. The start time is checked before killing, so a pgid
// reused by another process (after a reboot of the host, for example) is never
// signalled.

const (
	// sudoPGIDMarker prefixes the line printed by the sudo wrapper:
	// "SUDO-PGID=<pgid>:<starttime>"
	sudoPGIDMarker = "SUDO-PGID="
	// sudoPGIDMarkerMaxLine bounds the marker line, a longer line is not ours
	sudoPGIDMarkerMaxLine = 64

	remoteKillDoneMarker     = "SUDO-KILL-DONE"
	remoteKillMismatchMarker = "SUDO-KILL-MISMATCH"
	remoteKillNoProcMarker   = "SUDO-KILL-NOPROC"
)

// sudoWrapperPGIDSnippet is run by the sudo wrapper before the command. It
// prints the sudoPGIDMarker line: the process group of the command tree (sshd
// starts every session in its own process group, sudo and the command inherit
// it) and the start time of the group leader, field 22 of /proc/<pgid>/stat.
//
// The snippet is embedded into a single-quoted "bash -c" argument, so it must
// not contain single quotes. "sudo -i" passes the command through the login
// shell of the target user, which expands "$name", "$N" and "$$" before bash
// sees them (sudo escapes every special character except "$"), so only the
// "${name}" and "$(...)" forms may be used here.
const sudoWrapperPGIDSnippet = `__st=$(</proc/self/stat); __st=${__st##*) }; set -- ${__st}; __pg=${3}; ` +
	`__st=$(</proc/${__pg}/stat); __st=${__st##*) }; set -- ${__st}; ` +
	`echo "` + sudoPGIDMarker + `${__pg}:${20}"; set --; unset __st __pg`

// remoteProcessInfo identifies the process group of a sudo command on the remote
type remoteProcessInfo struct {
	PGID      int
	StartTime string
}

func (i remoteProcessInfo) String() string {
	return fmt.Sprintf("pgid %d started at %s", i.PGID, i.StartTime)
}

// remoteProcess holds the remoteProcessInfo of a sudo command once the wrapper
// reported it, and lets the signal senders wait for it
type remoteProcess struct {
	mu   sync.Mutex
	info remoteProcessInfo
	ok   bool

	readyOnce sync.Once
	ready     chan struct{}
}

func newRemoteProcess() *remoteProcess {
	return &remoteProcess{
		ready: make(chan struct{}),
	}
}

// setFromMarkerLine parses "<pgid>:<starttime>" (the marker line without the
// prefix) and publishes it. A line which cannot be parsed marks the process as
// unavailable.
func (p *remoteProcess) setFromMarkerLine(line []byte) error {
	info, err := parseSudoPGIDLine(line)
	if err != nil {
		p.markUnavailable()
		return err
	}

	p.mu.Lock()
	p.info = info
	p.ok = true
	p.mu.Unlock()

	p.readyOnce.Do(func() { close(p.ready) })
	return nil
}

// markUnavailable unblocks the waiters without an info: the wrapper did not
// report the process group (no /proc on the remote, stream closed, ...)
func (p *remoteProcess) markUnavailable() {
	p.readyOnce.Do(func() { close(p.ready) })
}

// get returns the info if it was published
func (p *remoteProcess) get() (remoteProcessInfo, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.info, p.ok
}

// wait blocks until the info is published, the process is marked unavailable,
// stop is closed or the timeout passes
func (p *remoteProcess) wait(timeout time.Duration, stop <-chan struct{}) (remoteProcessInfo, bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-p.ready:
	case <-stop:
	case <-timer.C:
	}

	return p.get()
}

func parseSudoPGIDLine(line []byte) (remoteProcessInfo, error) {
	pgidStr, startTime, found := strings.Cut(strings.TrimSpace(string(line)), ":")
	if !found {
		return remoteProcessInfo{}, fmt.Errorf("no ':' in sudo pgid marker line %q", line)
	}

	pgid, err := strconv.Atoi(pgidStr)
	if err != nil || pgid <= 1 {
		return remoteProcessInfo{}, fmt.Errorf("invalid pgid in sudo pgid marker line %q", line)
	}

	if _, err := strconv.ParseUint(startTime, 10, 64); err != nil {
		return remoteProcessInfo{}, fmt.Errorf("invalid start time in sudo pgid marker line %q", line)
	}

	return remoteProcessInfo{PGID: pgid, StartTime: startTime}, nil
}

// remoteKillScript returns the command run as root on the remote to deliver sigs
// to the process group of proc. The group is signalled only if its leader is
// still the process reported by the wrapper (same start time), otherwise the
// pgid was reused and nothing is killed. The script reports the outcome with
// the remoteKill*Marker lines.
//
// The script runs through the sudo wrapper: the same restrictions as for
// sudoWrapperPGIDSnippet apply.
func remoteKillScript(proc remoteProcessInfo, sigs []gossh.Signal) string {
	kills := make([]string, 0, len(sigs))
	for _, sig := range sigs {
		kills = append(kills, fmt.Sprintf("kill -s %s -- -%d", sig, proc.PGID))
	}

	return fmt.Sprintf(
		`if [ -r /proc/%[1]d/stat ]; then `+
			`__st=$(</proc/%[1]d/stat); __st=${__st##*) }; set -- ${__st}; `+
			`if [ "${20}" = "%[2]s" ]; then %[3]s; echo %[4]s; else echo %[5]s; fi; `+
			`else echo %[6]s; fi`,
		proc.PGID,
		proc.StartTime,
		strings.Join(kills, "; "),
		remoteKillDoneMarker,
		remoteKillMismatchMarker,
		remoteKillNoProcMarker,
	)
}

// markerLineCapture removes one "<pattern><line>\n" from a byte stream fed in
// arbitrary chunks and hands the line to onLine. Bytes of a partial pattern
// match are withheld until the match succeeds or fails, so the consumers of
// the stream never see a piece of the marker. If the stream ends or the line
// grows over maxLine before its newline, everything withheld is given back to
// the stream and onMissing is called.
type markerLineCapture struct {
	pattern []byte
	maxLine int

	onLine    func(line []byte)
	onMissing func()

	state     int // number of pattern bytes matched and withheld
	capturing bool
	line      []byte
	done      bool
}

func newMarkerLineCapture(pattern string, maxLine int, onLine func(line []byte), onMissing func()) *markerLineCapture {
	return &markerLineCapture{
		pattern:   []byte(pattern),
		maxLine:   maxLine,
		onLine:    onLine,
		onMissing: onMissing,
	}
}

// Feed consumes the next chunk of the stream and returns the bytes which go on
// to the consumers. The returned slice never aliases chunk while the capture
// is in progress.
func (m *markerLineCapture) Feed(chunk []byte) []byte {
	if m.done {
		return chunk
	}

	out := make([]byte, 0, len(chunk))
	for _, b := range chunk {
		out = m.feedByte(out, b)
	}

	return out
}

func (m *markerLineCapture) feedByte(out []byte, b byte) []byte {
	if m.done {
		return append(out, b)
	}

	if m.capturing {
		if b == '\n' {
			line := bytes.TrimRight(m.line, "\r")
			m.finish()
			if m.onLine != nil {
				m.onLine(line)
			}
			return out
		}

		m.line = append(m.line, b)
		if len(m.line) > m.maxLine {
			// too long for the marker line: not ours, give it back
			out = append(out, m.pattern...)
			out = append(out, m.line...)
			m.giveUp()
		}
		return out
	}

	if b == m.pattern[m.state] {
		m.state++
		if m.state == len(m.pattern) {
			m.state = 0
			m.capturing = true
		}
		return out
	}

	if m.state > 0 {
		// the withheld prefix is not the marker: release it and match the byte
		// from the beginning of the pattern
		out = append(out, m.pattern[:m.state]...)
		m.state = 0
		return m.feedByte(out, b)
	}

	return append(out, b)
}

// Flush ends the capture at the end of the stream and returns the withheld bytes
func (m *markerLineCapture) Flush() []byte {
	if m.done {
		return nil
	}

	var out []byte
	switch {
	case m.capturing:
		out = append(out, m.pattern...)
		out = append(out, m.line...)
	case m.state > 0:
		out = append(out, m.pattern[:m.state]...)
	}

	m.giveUp()
	return out
}

func (m *markerLineCapture) finish() {
	m.done = true
	m.capturing = false
	m.line = nil
	m.state = 0
}

func (m *markerLineCapture) giveUp() {
	m.finish()
	if m.onMissing != nil {
		m.onMissing()
	}
}
