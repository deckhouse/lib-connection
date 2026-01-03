#!/usr/bin/env bash

# Copyright 2026 Flant JSC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

source "$(pwd)/hack/utils.sh"

check_all_deps

kind_bin="$(kind_bin_path)"

function get_kind_clusters() {
  local clusters="$("$kind_bin" get clusters | grep --color=never "test-connection" || true)"
  clusters="$(trim_spaces "$clusters")"
  if [[ "$clusters" == "No kind clusters found." ]]; then
    echo -n ""
    return 0
  fi

  echo -n "$clusters"
  return 0
}

function rm_kind_clusters() {
  echo "Remove kind clusters $@"
  "$kind_bin" delete clusters "$@"
  return $?
}

do_in_cycle "remove tests kind clusters" get_kind_clusters rm_kind_clusters

echo "Kind clusters cleanup done!"
exit 0
