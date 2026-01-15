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

run_tests=""

if [ -n "$RUN_TEST" ]; then
  echo "Found RUN_TEST env. Run only $RUN_TEST test"
  run_tests="-run ^$RUN_TEST\$"
fi

function module_prefix_for_current_dir() {
    echo -n "$(grep -oP 'module .*$' go.mod | sed 's|module ||')"
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
    packages="$(go list ./... | grep -v -P "$expect_pkg")"
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

  local failed=""

  while IFS= read -r p; do
    local pkg_dir="${p#$prefix}"
    if [ -z "$pkg_dir" ]; then
      echo "Package $p cannot have dir after trim $prefix"
      return 1
    fi

    local full_pkg_path="${run_dir}${pkg_dir}"

    echo "Run tests in $full_pkg_path"
    cd "$full_pkg_path"
    if ! echo "test -timeout 30m -v -p 1 $run_tests" | xargs go; then
      all_failed_tests="$(echo -e "${all_failed_tests}\nTests in ${p} failed")"
    fi
  done <<< "$packages"
}

root_dir="$(pwd)"
declare -A tests_dirs=(
  # expect /validation after license validation run
  ["$root_dir"]="$(module_prefix_for_current_dir)/validation\$"
  ["${root_dir}/tests"]=""
)

for tdir in "${!tests_dirs[@]}"; do
  run_tests_in_dir "$tdir" "${tests_dirs[$tdir]}"
done

if [ -n "$all_failed_tests" ]; then
  echo -e "\033[31m${all_failed_tests}\033[0m"
  exit 1
fi


echo -e "\033[32mPassed!\033[0m"
exit 0
