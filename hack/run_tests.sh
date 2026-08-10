#!/usr/bin/env bash

# Copyright 2025 Flant JSC
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
check_go
pull_image

# Absolute path: run_tests_in_dir cd's into module dirs (repo root and ./tests).
gotestsum_bin="$(gotestsum_bin_path)"

run_tests=""

if [ -n "$RUN_TEST" ]; then
  echo "Found RUN_TEST env. Run only $RUN_TEST test"
  run_tests="-run ^$RUN_TEST\$"
fi

# How many packages go test builds/runs concurrently (go test -p).
package_parallelism="${TESTS_PACKAGE_PARALLELISM:-2}"
# How many parallel tests run concurrently inside one package (go test -parallel).
test_parallelism="${TESTS_PARALLELISM:-4}"

if [ "${RUN_TESTS_SEQUENTIALLY:-}" == "true" ]; then
  echo "Found RUN_TESTS_SEQUENTIALLY env. Run packages and tests sequentially"
  package_parallelism=1
  test_parallelism=1
fi

function module_prefix_for_current_dir() {
    echo -n "$(sed -n 's|^module ||p' go.mod | head -n 1)"
}

all_failed_tests=""

function run_tests_in_dir() {
  local run_dir="$1"
  local expect_pkg="$2"

  if [ -z "$run_dir" ]; then
    echo "run_dir is empty"
    return 1
  fi

  if ! run_dir="$(realpath "$run_dir")"; then
    echo "Cannot get real path for $run_dir"
    return 1
  fi

  cd "$run_dir"

  local packages=""

  if [ -n "$expect_pkg" ]; then
    packages="$(go list ./... | grep -v -E "$expect_pkg")"
  else
    packages="$(go list ./...)"
  fi

  local prefix="$(module_prefix_for_current_dir)"

  if [ -z "$(trim_spaces "$packages")" ]; then
    echo -e '\033[1;33m!!!\033[0m'
    echo -e "\033[1;33mNot found packages in ${run_dir} with module ${prefix}. Skip go tests for ${run_dir}\033[0m"
    echo -e '\033[1;33m!!!\033[0m'
    return 0
  fi

  echo "Found packages: ${packages[@]} in ${run_dir} with module ${prefix}"

  echo "Run tests in ${run_dir} (-p ${package_parallelism} -parallel ${test_parallelism})"
  if ! "$gotestsum_bin" -- -timeout 35m -v -p "$package_parallelism" -parallel "$test_parallelism" $run_tests $packages; then
    all_failed_tests="$(echo -e "${all_failed_tests}\nTests in ${prefix} failed")"
  fi
}

root_dir="$(pwd)"

# expect /validation after license validation run
run_tests_in_dir "$root_dir" "$(module_prefix_for_current_dir)/validation\$"
run_tests_in_dir "${root_dir}/tests" ""

if [ -n "$all_failed_tests" ]; then
  echo -e "\033[31m${all_failed_tests}\033[0m"
  exit 1
fi


echo -e "\033[32mPassed!\033[0m"
exit 0
