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
	"slices"
	"strings"
	"time"

	gossh "github.com/deckhouse/lib-gossh"
)

// A sudo command runs as root, so sshd cannot signal it on behalf of the SSH user.
// The sudo wrapper runs it in its own process group next to a root watchdog which
// reads signal names from stdin and kills the group when stdin is closed.

// sudoSuccessPattern is printed by the wrapper when sudo has started it
const sudoSuccessPattern = "SUDO-SUCCESS"

var (
	// sudoStopGracePeriod is the time between SIGINT and SIGKILL after the session is closed
	sudoStopGracePeriod = 5 * time.Second

	sudoWatchdogTick = 100 * time.Millisecond
)

// sudoControlSignals are the signals the watchdog accepts from stdin
var sudoControlSignals = []gossh.Signal{
	gossh.SIGABRT,
	gossh.SIGALRM,
	gossh.SIGFPE,
	gossh.SIGHUP,
	gossh.SIGILL,
	gossh.SIGINT,
	gossh.SIGKILL,
	gossh.SIGPIPE,
	gossh.SIGQUIT,
	gossh.SIGSEGV,
	gossh.SIGTERM,
	gossh.SIGUSR1,
	gossh.SIGUSR2,
}

// sudoRelayedSignals are the signals sudo relays to the wrapper, the wrapper passes them to the command
var sudoRelayedSignals = []gossh.Signal{
	gossh.SIGHUP,
	gossh.SIGINT,
	gossh.SIGQUIT,
	gossh.SIGTERM,
	gossh.SIGUSR1,
	gossh.SIGUSR2,
}

// sudoWrapperScript returns the "bash -c" script run by sudo for cmdLine. It goes
// through the login shell of "sudo -i": no single quotes, and "$" only as "${name}" or "$(".
func sudoWrapperScript(cmdLine string, grace time.Duration) string {
	steps := max(int(grace/sudoWatchdogTick), 1)

	return "echo " + sudoSuccessPattern + "; set -m; " +
		// the command gets its own process group and does not share stdin with the watchdog
		"( " + cmdLine + " ) </dev/null & __pg=${!}; " +
		"{ trap \"exit 0\" TERM; " +
		"while read -r __s; do case ${__s} in " + joinSignals(sudoControlSignals, "|") +
		") kill -s ${__s} -- -${__pg} 2>/dev/null;; esac; done; " +
		// stdin is closed: the session is gone, stop the command and do not let the wrapper cancel it
		"trap \"\" TERM; kill -s INT -- -${__pg} 2>/dev/null; " +
		fmt.Sprintf("__i=0; while [ ${__i} -lt %d ] && kill -0 -- -${__pg} 2>/dev/null; do sleep %s; __i=$((__i+1)); done; ",
			steps, formatSeconds(sudoWatchdogTick)) +
		"kill -s KILL -- -${__pg} 2>/dev/null; } <&0 >/dev/null 2>&1 & __w=${!}; set +m; " +
		"for __s in " + joinSignals(sudoRelayedSignals, " ") +
		"; do trap \"kill -s ${__s} -- -${__pg} 2>/dev/null\" ${__s}; done; " +
		"while :; do wait ${__pg} 2>/dev/null; __rc=${?}; kill -0 ${__pg} 2>/dev/null || break; done; " +
		"kill ${__w} 2>/dev/null; exit ${__rc}"
}

// sudoControlLine returns the stdin line which makes the watchdog send sig to the command
func sudoControlLine(sig gossh.Signal) (string, error) {
	if !slices.Contains(sudoControlSignals, sig) {
		return "", fmt.Errorf("signal %q is not supported for sudo commands", sig)
	}

	return string(sig) + "\n", nil
}

func joinSignals(sigs []gossh.Signal, sep string) string {
	names := make([]string, 0, len(sigs))
	for _, sig := range sigs {
		names = append(names, string(sig))
	}

	return strings.Join(names, sep)
}

func formatSeconds(d time.Duration) string {
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.3f", d.Seconds()), "0"), ".")
}
