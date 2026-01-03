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

function trim_spaces() {
  local v="$1"
  # Remove leading whitespace
  v="${v#"${v%%[![:space:]]*}"}"

  # Remove trailing whitespace
  v="${v%"${v##*[![:space:]]}"}"

  echo -n "$v"
}

function do_in_cycle(){
  local msg="$1"
  local get_arguments="$2"
  local action="$3"

  if [ -z "$msg" ]; then
    echo "msg is empty"
    exit 1
  fi

  if [ -z "$get_arguments" ]; then
    echo "get_arguments is empty"
    exit 1
  fi

  if [ -z "$action" ]; then
    echo "action is empty"
    exit 1
  fi

  local attempts=10

  echo "Starting $msg with $attempts attempts"

  local sleep_time=2
  local current_attempt=1

  while [[ -n "$(trim_spaces "$("$get_arguments")")" ]]; do
    if [[ "$current_attempt" == "$attempts" ]]; then
      echo "All attempts $attempts failed for ${msg}. Exit"
      exit 1
    fi

    if ! $action $("$get_arguments"); then
      echo "Attempt ${current_attempt}: $msg failed. Sleep ${sleep_time} before next attempt"
      sleep "$sleep_time"
    fi

    ((current_attempt++))
  done

  echo "$msg done!"
  return 0
}

function check_go() {
  if ! command -v go; then
    echo "Go not found!"
    exit 1
  fi
}

function check_docker() {
  if ! command -v docker; then
    echo "Docker not found!"
    exit 1
  fi
}

function kind_bin_path() {
  echo -n "$(pwd)/bin/kind"
}

function check_kind() {
  local bin_path="$(kind_bin_path)"
  if ! [ -x "$bin_path" ]; then
    echo "Kind not installed! You should run 'make bin/kind' before"
    exit 1
  fi
}

function check_all_deps() {
    check_docker && check_kind
}