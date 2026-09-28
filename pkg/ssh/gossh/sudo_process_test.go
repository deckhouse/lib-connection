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
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	gossh "github.com/deckhouse/lib-gossh"
	"github.com/stretchr/testify/require"
)

// bareDollarRe matches "$name", "$N" and "$$": the login shell started by
// "sudo -i" expands them before bash gets the command
var bareDollarRe = regexp.MustCompile(`\$[A-Za-z0-9_$]`)

func TestSudoWrapperSnippetsAreSafeForSudoLoginShell(t *testing.T) {
	scripts := map[string]string{
		"pgid snippet": sudoWrapperPGIDSnippet,
		"kill script":  remoteKillScript(remoteProcessInfo{PGID: 4242, StartTime: "123456"}, []gossh.Signal{gossh.SIGINT, gossh.SIGKILL}),
	}

	for name, script := range scripts {
		t.Run(name, func(t *testing.T) {
			require.NotContains(t, script, "'", "script is embedded into a single-quoted bash -c argument")
			require.Empty(t, bareDollarRe.FindAllString(script, -1), "only ${name} and $(...) survive the sudo -i login shell")
		})
	}
}

func TestRemoteKillScript(t *testing.T) {
	script := remoteKillScript(remoteProcessInfo{PGID: 4242, StartTime: "123456"}, []gossh.Signal{gossh.SIGINT, gossh.SIGKILL})

	require.Contains(t, script, "/proc/4242/stat")
	require.Contains(t, script, `[ "${20}" = "123456" ]`)
	require.Contains(t, script, "kill -s INT -- -4242; kill -s KILL -- -4242")
	require.Contains(t, script, remoteKillDoneMarker)
	require.Contains(t, script, remoteKillMismatchMarker)
	require.Contains(t, script, remoteKillNoProcMarker)
}

func TestParseSudoPGIDLine(t *testing.T) {
	cases := []struct {
		line    string
		want    remoteProcessInfo
		wantErr bool
	}{
		{line: "4242:123456", want: remoteProcessInfo{PGID: 4242, StartTime: "123456"}},
		{line: "  4242:123456 \r", want: remoteProcessInfo{PGID: 4242, StartTime: "123456"}},
		{line: ":", wantErr: true},
		{line: "", wantErr: true},
		{line: "4242", wantErr: true},
		{line: "abc:123", wantErr: true},
		{line: "4242:", wantErr: true},
		{line: "4242:abc", wantErr: true},
		{line: "1:123", wantErr: true},
		{line: "-5:123", wantErr: true},
	}

	for _, c := range cases {
		t.Run(fmt.Sprintf("%q", c.line), func(t *testing.T) {
			got, err := parseSudoPGIDLine([]byte(c.line))
			if c.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, c.want, got)
		})
	}
}

func feedInChunks(capture *markerLineCapture, stream string, chunkSize int) string {
	var out strings.Builder
	data := []byte(stream)
	for start := 0; start < len(data); start += chunkSize {
		end := min(start+chunkSize, len(data))
		out.Write(capture.Feed(data[start:end]))
	}
	out.Write(capture.Flush())
	return out.String()
}

func TestMarkerLineCapture(t *testing.T) {
	cases := []struct {
		title       string
		stream      string
		wantOut     string
		wantLine    string
		wantMissing bool
	}{
		{
			title:    "marker first",
			stream:   "SUDO-PGID=4242:123456\nSUDO-SUCCESS\nhi\n",
			wantOut:  "SUDO-SUCCESS\nhi\n",
			wantLine: "4242:123456",
		},
		{
			title:    "marker after login shell noise",
			stream:   "Welcome!\nSUDO-PGID=4242:123456\nSUDO-SUCCESS\nhi\n",
			wantOut:  "Welcome!\nSUDO-SUCCESS\nhi\n",
			wantLine: "4242:123456",
		},
		{
			title:    "marker with CRLF",
			stream:   "SUDO-PGID=4242:123456\r\nSUDO-SUCCESS\r\n",
			wantOut:  "SUDO-SUCCESS\r\n",
			wantLine: "4242:123456",
		},
		{
			title:    "partial pattern before the marker is released",
			stream:   "SUDO-PSUDO-PGID=4242:123456\nhi\n",
			wantOut:  "SUDO-Phi\n",
			wantLine: "4242:123456",
		},
		{
			title:    "only the first marker is captured",
			stream:   "SUDO-PGID=1:2\nSUDO-PGID=3:4\n",
			wantOut:  "SUDO-PGID=3:4\n",
			wantLine: "1:2",
		},
		{
			title:       "no marker",
			stream:      "SUDO-SUCCESS\nhi\nSUDO-PG",
			wantOut:     "SUDO-SUCCESS\nhi\nSUDO-PG",
			wantMissing: true,
		},
		{
			title:       "stream ends inside the marker line",
			stream:      "hi\nSUDO-PGID=4242:12",
			wantOut:     "hi\nSUDO-PGID=4242:12",
			wantMissing: true,
		},
		{
			title:       "too long marker line is given back",
			stream:      "SUDO-PGID=" + strings.Repeat("x", sudoPGIDMarkerMaxLine+1) + "\nhi\n",
			wantOut:     "SUDO-PGID=" + strings.Repeat("x", sudoPGIDMarkerMaxLine+1) + "\nhi\n",
			wantMissing: true,
		},
		{
			title:       "empty stream",
			stream:      "",
			wantOut:     "",
			wantMissing: true,
		},
	}

	for _, c := range cases {
		for _, chunkSize := range []int{1, 2, 3, 7, 16, 1024} {
			t.Run(fmt.Sprintf("%s/chunk=%d", c.title, chunkSize), func(t *testing.T) {
				var (
					line    string
					lines   int
					missing int
				)
				capture := newMarkerLineCapture(
					sudoPGIDMarker,
					sudoPGIDMarkerMaxLine,
					func(l []byte) { line = string(l); lines++ },
					func() { missing++ },
				)

				out := feedInChunks(capture, c.stream, chunkSize)

				require.Equal(t, c.wantOut, out)
				if c.wantMissing {
					require.Equal(t, 0, lines, "line must not be reported")
					require.Equal(t, 1, missing, "missing must be reported once")
					return
				}
				require.Equal(t, 1, lines, "line must be reported once")
				require.Equal(t, c.wantLine, line)
				require.Equal(t, 0, missing, "missing must not be reported")
			})
		}
	}
}

func TestRemoteProcessWait(t *testing.T) {
	t.Run("published info", func(t *testing.T) {
		p := newRemoteProcess()
		go func() {
			time.Sleep(50 * time.Millisecond)
			require.NoError(t, p.setFromMarkerLine([]byte("4242:123456")))
		}()

		info, ok := p.wait(5*time.Second, nil)
		require.True(t, ok)
		require.Equal(t, remoteProcessInfo{PGID: 4242, StartTime: "123456"}, info)
	})

	t.Run("unavailable", func(t *testing.T) {
		p := newRemoteProcess()
		p.markUnavailable()

		_, ok := p.wait(5*time.Second, nil)
		require.False(t, ok)
	})

	t.Run("invalid line marks unavailable", func(t *testing.T) {
		p := newRemoteProcess()
		require.Error(t, p.setFromMarkerLine([]byte(":")))

		_, ok := p.wait(5*time.Second, nil)
		require.False(t, ok)
	})

	t.Run("stop channel", func(t *testing.T) {
		p := newRemoteProcess()
		stop := make(chan struct{})
		close(stop)

		start := time.Now()
		_, ok := p.wait(5*time.Second, stop)
		require.False(t, ok)
		require.Less(t, time.Since(start), time.Second)
	})

	t.Run("timeout", func(t *testing.T) {
		p := newRemoteProcess()

		start := time.Now()
		_, ok := p.wait(50*time.Millisecond, nil)
		require.False(t, ok)
		require.Less(t, time.Since(start), time.Second)
	})
}
